"""Policy validation, hashing and per-device reconciliation.

A policy is a typed JSON document that the agent knows how to apply idempotently.
Everything the agent creates is tagged so it can update or remove only what it owns.
See docs/POLICIES.md for the schema of each type.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import (
    Device,
    Policy,
    PolicyAssignment,
    PolicyType,
    Task,
    TaskStatus,
    TaskType,
    device_group_members,
)

ALIAS_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,31}$")
IFACE_RE = re.compile(r"^(wan|lan|opt\d{1,3}|floating|ipsec|openvpn|wireguard|enc0)$")
PKG_NAME_RE = re.compile(r"^pfSense-pkg-[A-Za-z0-9_.+-]{1,64}$")
CONFIG_PATH_RE = re.compile(r"^[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-]+)*$")
# Port alias entries: a port or a range (1000:2000).
PORT_RE = re.compile(r"^([0-9]{1,5}(:[0-9]{1,5})?|[A-Za-z0-9_]{1,31})$")
# Ports in rules and port forwards: also 1000-2000, as pfSense stores ranges there, and port aliases.
RULE_PORT_RE = re.compile(r"^([0-9]{1,5}([:-][0-9]{1,5})?|[A-Za-z0-9_]{1,31})$")

ALIAS_FORM_TYPES = ("host", "network", "port", "url", "urltable")  # offered in the forms
ALIAS_TYPES = {"host", "network", "port", "url", "urltable", "url_ports", "urltable_ports"}
RULE_TYPES = {"pass", "block", "reject"}
RULE_PROTOCOLS = {"any", "tcp", "udp", "tcp/udp", "icmp", "esp", "ah", "gre", "ipv6", "igmp", "pim", "ospf", "carp", "pfsync"}
IP_PROTOCOLS = {"inet", "inet6", "inet46"}
SYSTEM_KEYS = {
    "hostname",
    "domain",
    "timezone",
    "timeservers",
    "dnsservers",
    "dnsallowoverride",
    "language",
}
RELOADABLE = {"filter", "dns", "ntp", "webgui", "hostname", "routing", "unbound", "dnsmasq"}
# Config paths that a config_set policy may never touch, nor any path above them (writing "system"
# whole would replace its users): identity and accounts, this package's local permissions, and
# everything that runs commands as root (shellcmd, cron, the Filer and Sudo packages).
CONFIG_SET_DENY_PREFIXES = (
    "system/user",
    "system/group",
    "system/authserver",
    "system/shellcmd",
    "system/earlyshellcmd",
    "system/afterfilterchangeshellcmd",
    "cert",
    "ca",
    "cron",
    "installedpackages/comsense",
    "installedpackages/shellcmdsettings",
    "installedpackages/filer",
    "installedpackages/sudo",
    "installedpackages/cron",
)


def config_path_protected(path: str) -> bool:
    """A protected path, one under it, or one above it."""
    return any(path == p or path.startswith(p + "/") or p.startswith(path + "/") for p in CONFIG_SET_DENY_PREFIXES)


TYPE_LABELS = {
    PolicyType.aliases: "Aliases",
    PolicyType.firewall_rules: "Firewall rules",
    PolicyType.port_forward: "Port forwards",
    PolicyType.system: "System settings",
    PolicyType.packages: "Packages",
    PolicyType.config_set: "Config values",
    PolicyType.notifications: "Email notifications",
    PolicyType.ssh: "SSH access",
}


def endpoint_text(ep: dict[str, Any] | None) -> str:
    """{"network": "lan"} -> "lan net", {"network": "wanip"} -> "wan address", ..."""
    ep = ep or {}
    neg = "!" if ep.get("not") else ""
    if ep.get("address"):
        return neg + ep["address"]
    net = ep.get("network")
    if net == "(self)":
        return neg + "this firewall"
    if net:
        return neg + (f"{net[:-2]} address" if net.endswith("ip") else f"{net} net")
    return neg + "any"


class PolicyError(ValueError):
    pass


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def policy_hash(policy: Policy) -> str:
    doc = {"type": policy.type.value, "content": policy.content}
    return hashlib.sha256(canonical_json(doc).encode()).hexdigest()


def policy_payload(policy: Policy) -> dict[str, Any]:
    return {
        "policy": {
            "id": policy.id,
            "name": policy.name,
            "type": policy.type.value,
            "revision": policy.revision,
            "hash": policy_hash(policy),
            "content": policy.content,
        }
    }


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise PolicyError(message)


def _str_list(value: Any, field: str) -> list[str]:
    _require(isinstance(value, list), f"{field} must be a list")
    _require(all(isinstance(v, str) for v in value), f"{field} must contain only strings")
    return value


def _validate_endpoint(ep: Any, where: str) -> None:
    _require(isinstance(ep, dict), f"{where} must be an object")
    allowed = {"any", "address", "network", "port", "not"}
    unknown = set(ep) - allowed
    _require(not unknown, f"{where}: unknown keys {sorted(unknown)}")
    picked = [k for k in ("any", "address", "network") if ep.get(k)]
    _require(len(picked) <= 1, f"{where}: use only one of any/address/network")
    if "address" in ep:
        addr = ep["address"]
        _require(isinstance(addr, str) and addr, f"{where}.address must be a string")
        if not ALIAS_NAME_RE.match(addr):
            try:
                ipaddress.ip_network(addr, strict=False)
            except ValueError as exc:
                raise PolicyError(f"{where}.address is not an IP, CIDR or alias name") from exc
    if "network" in ep:
        _require(
            isinstance(ep["network"], str) and re.match(r"^(\(self\)|[a-z0-9]+(ip)?)$", ep["network"]),
            f"{where}.network must be an interface network such as 'lan' or 'wanip'",
        )
    if "port" in ep:
        _require(
            isinstance(ep["port"], str) and RULE_PORT_RE.match(ep["port"]),
            f"{where}.port must be a port, range (1000:2000) or port alias",
        )


def _validate_aliases(content: dict[str, Any]) -> None:
    aliases = content.get("aliases")
    _require(isinstance(aliases, list) and aliases, "aliases: 'aliases' must be a non-empty list")
    names = set()
    for i, alias in enumerate(aliases):
        where = f"aliases[{i}]"
        _require(isinstance(alias, dict), f"{where} must be an object")
        name = alias.get("name", "")
        _require(isinstance(name, str) and ALIAS_NAME_RE.match(name), f"{where}.name is invalid")
        _require(name not in names, f"{where}.name '{name}' is duplicated")
        names.add(name)
        _require(alias.get("type") in ALIAS_TYPES, f"{where}.type must be one of {sorted(ALIAS_TYPES)}")
        _str_list(alias.get("address", []), f"{where}.address")
        if "detail" in alias:
            _str_list(alias["detail"], f"{where}.detail")
    _require(isinstance(content.get("remove_unlisted", True), bool), "remove_unlisted must be a boolean")


def _validate_rules(content: dict[str, Any]) -> None:
    rules = content.get("rules")
    _require(isinstance(rules, list) and rules, "firewall_rules: 'rules' must be a non-empty list")
    _require(content.get("position", "top") in {"top", "bottom"}, "position must be 'top' or 'bottom'")
    for i, rule in enumerate(rules):
        where = f"rules[{i}]"
        _require(isinstance(rule, dict), f"{where} must be an object")
        iface = rule.get("interface", "")
        _require(isinstance(iface, str) and IFACE_RE.match(iface), f"{where}.interface is invalid")
        _require(rule.get("type", "pass") in RULE_TYPES, f"{where}.type must be pass, block or reject")
        _require(rule.get("ipprotocol", "inet") in IP_PROTOCOLS, f"{where}.ipprotocol is invalid")
        _require(rule.get("protocol", "any") in RULE_PROTOCOLS, f"{where}.protocol is invalid")
        _require(isinstance(rule.get("descr", ""), str), f"{where}.descr must be a string")
        _validate_endpoint(rule.get("source", {"any": True}), f"{where}.source")
        _validate_endpoint(rule.get("destination", {"any": True}), f"{where}.destination")
        if rule.get("interface") == "floating":
            _require(
                isinstance(rule.get("floating_interfaces", []), list),
                f"{where}.floating_interfaces must be a list",
            )


NAT_PROTOCOLS = {"tcp", "udp", "tcp/udp"}


def _validate_port_forwards(content: dict[str, Any]) -> None:
    rules = content.get("rules")
    _require(isinstance(rules, list) and rules, "port_forward: 'rules' must be a non-empty list")
    _require(content.get("position", "top") in {"top", "bottom"}, "position must be 'top' or 'bottom'")
    for i, rule in enumerate(rules):
        where = f"rules[{i}]"
        _require(isinstance(rule, dict), f"{where} must be an object")
        iface = rule.get("interface", "wan")
        _require(isinstance(iface, str) and IFACE_RE.match(iface) and iface != "floating",
                 f"{where}.interface is invalid")
        _require(rule.get("protocol", "tcp") in NAT_PROTOCOLS, f"{where}.protocol must be tcp, udp or tcp/udp")
        _require(rule.get("ipprotocol", "inet") in {"inet", "inet6"}, f"{where}.ipprotocol is invalid")
        _validate_endpoint(rule.get("source", {"any": True}), f"{where}.source")
        dest = rule.get("destination", {"network": "wanip"})
        _validate_endpoint(dest, f"{where}.destination")
        _require(bool(dest.get("port")), f"{where}.destination.port (the external port) is required")
        target = rule.get("target", "")
        _require(isinstance(target, str) and target, f"{where}.target (the internal address) is required")
        if not ALIAS_NAME_RE.match(target):
            try:
                ipaddress.ip_address(target)
            except ValueError as exc:
                raise PolicyError(f"{where}.target must be an IP address or alias name") from exc
        local = rule.get("local_port", "")
        _require(isinstance(local, str) and RULE_PORT_RE.match(local), f"{where}.local_port must be a port or port alias")
        _require(isinstance(rule.get("descr", ""), str), f"{where}.descr must be a string")
        _require(isinstance(rule.get("disabled", False), bool), f"{where}.disabled must be a boolean")


def _validate_notifications(content: dict[str, Any]) -> None:
    _require(set(content) == {"smtp"} and isinstance(content["smtp"], bool),
             "notifications: content must be {\"smtp\": true or false}")


SSH_AUTH = ("password_or_key", "key_only", "password_and_key")
SSH_KEY_RE = re.compile(r"^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)"
                        r" [A-Za-z0-9+/]+={0,3}( [^\r\n]{0,200})?$")


def _validate_ssh(content: dict[str, Any]) -> None:
    """SSH (System > Advanced > Admin Access): on/off, port, how to log in, keys for the admin user."""
    unknown = set(content) - {"enabled", "port", "auth", "agent_forwarding", "admin_keys"}
    _require(not unknown, f"ssh: unknown keys {sorted(unknown)}")
    _require(isinstance(content.get("enabled"), bool), "ssh.enabled must be true or false")
    port = content.get("port", 22)
    _require(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535, "ssh.port must be 1 to 65535")
    _require(content.get("auth", "password_or_key") in SSH_AUTH, f"ssh.auth must be one of {list(SSH_AUTH)}")
    _require(isinstance(content.get("agent_forwarding", False), bool), "ssh.agent_forwarding must be true or false")
    keys = _str_list(content.get("admin_keys", []), "ssh.admin_keys")
    _require(len(keys) <= 20, "ssh.admin_keys allows at most 20 keys")
    for key in keys:
        _require(len(key) <= 16000 and bool(SSH_KEY_RE.match(key.strip())),
                 f"ssh.admin_keys: not an OpenSSH public key: {key[:40]}...")
    _require(not (content["enabled"] and content.get("auth") == "key_only" and not keys),
             "ssh: with key-only login, add at least one admin key, or the firewalls cannot be reached over SSH "
             "unless they already have keys")


def _alias_address_ok(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    first, dash, last = value.partition("-")
    if dash:
        try:
            ipaddress.ip_address(first)
            ipaddress.ip_address(last)
            return True
        except ValueError:
            return False
    if re.fullmatch(r"[0-9.:/]+", value):
        return False  # looks like an address but is not one
    return bool(re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$", value))  # a host name or another alias


_PORT_NUMBERS = re.compile(r"^[0-9]{1,5}(:[0-9]{1,5})?$")


def _more_entries(token: str) -> bool:
    """A further entry on a line: an address, network, range or port number, never a word of the description."""
    if _PORT_NUMBERS.match(token):
        return True
    return bool(re.fullmatch(r"[0-9a-fA-F.:/-]+", token)) and any(c.isdigit() for c in token) \
        and (":" in token or "." in token) and _alias_address_ok(token)


def parse_alias_entries(text: str) -> tuple[list[str], list[str]]:
    """Alias entries as typed or pasted: one or more per line, separated by new lines, commas, semicolons or
    spaces. After the first value on a line, further addresses, networks, ranges and ports are entries too;
    the rest of the line is a description, given to each entry from that line.
    "10.0.0.5 10.0.0.6 Front desk" -> (["10.0.0.5", "10.0.0.6"], ["Front desk", "Front desk"])."""
    values: list[str] = []
    notes: list[str] = []
    for line in re.split(r"[\n;,]", text or ""):
        tokens = line.split()
        if not tokens:
            continue
        line_values = [tokens[0]]
        rest = tokens[1:]
        while rest and _more_entries(rest[0]):
            line_values.append(rest.pop(0))
        note = " ".join(rest)[:200]
        for v in line_values:
            if v not in values:
                values.append(v)
                notes.append(note)
    return values, notes


def validate_alias(alias: dict[str, Any]) -> None:
    """One alias, as added or changed from a firewall's page."""
    try:
        _validate_aliases({"aliases": [alias]})
    except PolicyError as exc:
        raise PolicyError(str(exc).replace("aliases[0].", "")) from exc
    _require(bool(alias["address"]), "an alias needs at least one entry")
    if alias["type"] in {"host", "network"}:
        for value in alias["address"]:
            _require(_alias_address_ok(value), f"'{value}' is not an address, range, network, host name or alias")
    elif alias["type"] == "port":
        for value in alias["address"]:
            _require(bool(PORT_RE.match(value)), f"'{value}' is not a port, range (8000:8100) or port alias")
    else:
        _require(len(alias["address"]) == 1 and alias["address"][0].startswith(("https://", "http://")),
                 "a URL alias takes one http:// or https:// address")


def validate_port_forward_rule(rule: dict[str, Any]) -> None:
    """One port forward, as added from a firewall's page."""
    _validate_port_forwards({"rules": [rule]})


def _validate_system(content: dict[str, Any]) -> None:
    unknown = set(content) - SYSTEM_KEYS
    _require(not unknown, f"system: unknown keys {sorted(unknown)}")
    if "hostname" in content:
        _require(
            isinstance(content["hostname"], str)
            and re.match(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$", content["hostname"]),
            "system.hostname is invalid",
        )
    if "dnsservers" in content:
        for server in _str_list(content["dnsservers"], "system.dnsservers"):
            try:
                ipaddress.ip_address(server)
            except ValueError as exc:
                raise PolicyError(f"system.dnsservers: '{server}' is not an IP address") from exc
        _require(len(content["dnsservers"]) <= 8, "system.dnsservers allows at most 8 servers")
    if "dnsallowoverride" in content:
        _require(isinstance(content["dnsallowoverride"], bool), "system.dnsallowoverride must be a boolean")
    for key in ("domain", "timezone", "timeservers", "language"):
        if key in content:
            _require(
                isinstance(content[key], str) and re.match(r"^[A-Za-z0-9_./+\- ]{1,255}$", content[key]),
                f"system.{key} is invalid",
            )


def _validate_packages(content: dict[str, Any]) -> None:
    unknown = set(content) - {"install", "remove"}
    _require(not unknown, f"packages: unknown keys {sorted(unknown)}")
    install = _str_list(content.get("install", []), "packages.install")
    remove = _str_list(content.get("remove", []), "packages.remove")
    _require(install or remove, "packages: list at least one package")
    for name in install + remove:
        _require(PKG_NAME_RE.match(name), f"packages: '{name}' is not a pfSense package name")
    _require(not set(install) & set(remove), "packages: a package cannot be both installed and removed")


def _validate_config_set(content: dict[str, Any]) -> None:
    items = content.get("items")
    _require(isinstance(items, list) and items, "config_set: 'items' must be a non-empty list")
    for i, item in enumerate(items):
        where = f"items[{i}]"
        _require(isinstance(item, dict), f"{where} must be an object")
        path = item.get("path", "")
        _require(isinstance(path, str) and CONFIG_PATH_RE.match(path), f"{where}.path is invalid")
        _require(not config_path_protected(path), f"{where}.path '{path}' is protected and cannot be managed by policy")
        _require(("value" in item) != bool(item.get("delete")), f"{where} needs either value or delete")
    reload = _str_list(content.get("reload", []), "config_set.reload")
    _require(set(reload) <= RELOADABLE, f"config_set.reload must be a subset of {sorted(RELOADABLE)}")


_VALIDATORS = {
    PolicyType.aliases: _validate_aliases,
    PolicyType.firewall_rules: _validate_rules,
    PolicyType.system: _validate_system,
    PolicyType.packages: _validate_packages,
    PolicyType.config_set: _validate_config_set,
    PolicyType.port_forward: _validate_port_forwards,
    PolicyType.notifications: _validate_notifications,
    PolicyType.ssh: _validate_ssh,
}


def validate_policy(ptype: PolicyType, content: Any) -> None:
    _require(isinstance(content, dict), "policy content must be a JSON object")
    _VALIDATORS[ptype](content)


def desired_policies(db: Session, device: Device) -> list[Policy]:
    groups = select(device_group_members.c.group_id).where(device_group_members.c.device_id == device.id)
    conds = [
        PolicyAssignment.device_id == device.id,
        PolicyAssignment.all_devices.is_(True),
        PolicyAssignment.group_id.in_(groups),
    ]
    if device.organization_id is not None:
        conds.append(PolicyAssignment.organization_id == device.organization_id)
    # A subquery rather than JOIN + DISTINCT: PostgreSQL cannot compare the JSON content column.
    assigned = select(PolicyAssignment.policy_id).where(or_(*conds))
    stmt = select(Policy).where(Policy.enabled.is_(True), Policy.id.in_(assigned)).order_by(Policy.id)
    return list(db.scalars(stmt))


def _open_policy_tasks(db: Session, device: Device) -> dict[str, Task]:
    open_states = (TaskStatus.pending, TaskStatus.sent, TaskStatus.running)
    stmt = select(Task).where(
        Task.device_id == device.id,
        Task.type.in_((TaskType.apply_policy, TaskType.remove_policy)),
        Task.status.in_(open_states),
    )
    out: dict[str, Task] = {}
    for task in db.scalars(stmt):
        pid = task.payload.get("policy", {}).get("id") or task.payload.get("policy_id")
        out[str(pid)] = task
    return out


def reconcile_device_policies(
    db: Session, device: Device, actor: str = "system", changes_enabled: bool = False
) -> list[Task]:
    """Queue apply/remove tasks so the device converges on its assigned policies.

    Does nothing unless firewall changes are enabled. Returns the newly created
    tasks. The caller commits.
    """
    if not changes_enabled or "policy" not in (device.capabilities or []):
        return []
    open_tasks = _open_policy_tasks(db, device)
    applied = dict(device.applied_policies or {})
    # Changes the firewall rolled back are not re-sent until an operator clears them
    # (or the policy gets a new revision), so a change that cuts it off cannot loop.
    rolled_back = device.rolled_back_policies or {}
    created: list[Task] = []

    desired = desired_policies(db, device)
    desired_ids = {str(p.id) for p in desired}
    for policy in desired:
        pid = str(policy.id)
        digest = policy_hash(policy)
        existing = open_tasks.get(pid)
        if applied.get(pid) == digest or rolled_back.get(pid) == digest:
            continue
        if existing is not None:
            if existing.type == TaskType.apply_policy and existing.payload["policy"]["hash"] == digest:
                continue
            if existing.status == TaskStatus.pending:
                existing.status = TaskStatus.cancelled
                existing.output = "Superseded by a newer policy revision"
            else:
                continue  # let the in-flight task finish first
        task = Task(
            device_id=device.id, type=TaskType.apply_policy, payload=policy_payload(policy), created_by=actor
        )
        db.add(task)
        created.append(task)

    # The agent keeps its own record of what each policy created, so removal only needs the id.
    for pid in applied:
        if not str(pid).isdigit():
            continue  # reported by the firewall; ignore anything that is not a policy id
        if pid in desired_ids or pid in open_tasks or rolled_back.get(pid) == "remove":
            continue
        task = Task(
            device_id=device.id,
            type=TaskType.remove_policy,
            payload={"policy_id": int(pid)},
            created_by=actor,
        )
        db.add(task)
        created.append(task)
    return created
