"""Reading a firewall's current config.xml from its stored backups: the raw file for the
"View config" page (secrets hidden) and the port forwards, aliases and notification setting shown on
the firewall's Configuration page.

The agent uploads config.xml whenever it changes, so the backup whose SHA-256 matches the hash the
firewall last reported is its current configuration.
"""
from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Backup, Device
from .backups import BackupError, load_backup
from .policies import endpoint_text

# Elements whose text is a password, hash or private key.
SECRET_TAGS = (
    "password", "bcrypt-hash", "sha512-hash", "md5-hash", "nt-hash", "prv", "pre-shared-key", "psk",
    "shared_key", "tls", "privatekey", "secret", "ldap_bindpw", "radius_secret", "apikey", "authorizedkeys",
    "ipsecpsk", "passwordenc", "encryption_password", "auth_pass",
)
_SECRET_RE = re.compile(r"<(" + "|".join(re.escape(t) for t in SECRET_TAGS) + r")>(.*?)</\1>", re.S | re.I)

_nat_cache: OrderedDict[tuple[int, str], dict[str, Any]] = OrderedDict()
_NAT_CACHE_SIZE = 64


def current_backup(db: Session, device: Device) -> Backup | None:
    """The backup of the firewall's current config.xml, else its newest backup."""
    if device.config_sha256:
        match = db.scalar(select(Backup).where(Backup.device_id == device.id, Backup.sha256 == device.config_sha256))
        if match is not None:
            return match
    return db.scalar(select(Backup).where(Backup.device_id == device.id).order_by(Backup.created_at.desc()).limit(1))


def redact(xml: str) -> str:
    return _SECRET_RE.sub(lambda m: f"<{m.group(1)}>[hidden]</{m.group(1)}>", xml)


def _parse(xml: bytes) -> ET.Element:
    if b"<!DOCTYPE" in xml[:4096] or b"<!ENTITY" in xml[:65536]:
        raise BackupError("config.xml declares a DOCTYPE or entities; not parsed")
    try:
        return ET.fromstring(xml)
    except ET.ParseError as exc:
        raise BackupError(f"config.xml could not be parsed: {exc}") from exc


def _endpoint(el: ET.Element | None) -> tuple[str, str]:
    """(address text, port) of a <source>/<destination> element."""
    if el is None:
        return "any", ""
    ep: dict[str, Any] = {}
    for child in el:
        ep[child.tag] = (child.text or "").strip() or True
    return endpoint_text(ep), str(ep.get("port") or "")


def nat_fingerprint(interface: str, protocol: str, target: str, local_port: str, port: str, descr: str) -> str:
    """Identifies one port forward; the agent computes the same (csfm_nat_fingerprint)."""
    return hashlib.sha256("\x1f".join((interface, protocol, target, local_port, port, descr)).encode()).hexdigest()[:16]


def smtp_notifications_from_xml(xml: bytes) -> dict[str, Any]:
    """pfSense's own email notifications (System > Advanced > Notifications)."""
    smtp = _parse(xml).find("./notifications/smtp")
    return {
        "enabled": smtp is None or smtp.find("disable") is None,
        "server": (smtp.findtext("ipaddress") or "").strip() if smtp is not None else "",
        "to": (smtp.findtext("notifyemailaddress") or "").strip() if smtp is not None else "",
    }


def port_forwards_from_xml(xml: bytes) -> list[dict[str, Any]]:
    root = _parse(xml)
    out = []
    for rule in root.findall("./nat/rule"):
        def text(tag: str) -> str:
            return (rule.findtext(tag) or "").strip()

        src, src_port = _endpoint(rule.find("source"))
        dst, dst_port = _endpoint(rule.find("destination"))
        descr = text("descr")
        assoc = text("associated-rule-id")
        dest = rule.find("destination")
        fingerprint = nat_fingerprint(
            rule.findtext("interface") or "", rule.findtext("protocol") or "", rule.findtext("target") or "",
            rule.findtext("local-port") or "", (dest.findtext("port") if dest is not None else "") or "",
            rule.findtext("descr") or "")
        out.append({
            "interface": text("interface") or "wan",
            "protocol": text("protocol") or "any",
            "source": src + (f":{src_port}" if src_port else ""),
            "src": src,  # the parts, to fill in the edit form
            "src_port": src_port,
            "destination": dst,
            "port": dst_port,
            "target": text("target"),
            "local_port": text("local-port"),
            "descr": descr,
            "disabled": rule.find("disabled") is not None,
            "nordr": rule.find("nordr") is not None,
            "filter_rule": "pass" if assoc == "pass" else ("linked" if assoc else "none"),
            "managed": bool(text("comsense_policy")) or descr.startswith("[CSFM]"),
            "fingerprint": fingerprint,
        })
    return out


def aliases_from_xml(xml: bytes) -> list[dict[str, Any]]:
    """Aliases (Firewall > Aliases), with each entry's own description."""
    out = []
    for alias in _parse(xml).findall("./aliases/alias"):
        def text(tag: str) -> str:
            return (alias.findtext(tag) or "").strip()

        values = text("address").split() or ([text("url")] if text("url") else [])
        notes = text("detail").split("||") if text("detail") else []
        items = [{"value": v, "note": notes[i].strip() if i < len(notes) else ""} for i, v in enumerate(values)]
        out.append({
            "name": text("name"),
            "type": text("type") or "host",
            "entry_list": items,
            "entries": "\n".join(f"{e['value']} {e['note']}".strip() for e in items),
            "descr": text("descr"),
        })
    return sorted(out, key=lambda a: a["name"].lower())


def ddns_fingerprint(interface: str, provider: str, host: str, domain: str, descr: str) -> str:
    """Identifies one dynamic DNS client; the agent computes the same (csfm_ddns_fingerprint)."""
    return hashlib.sha256("\x1f".join((interface, provider, host, domain, descr)).encode()).hexdigest()[:16]


def ddns_from_xml(xml: bytes) -> list[dict[str, Any]]:
    """Services > Dynamic DNS clients (passwords are never read out)."""
    out = []
    for d in _parse(xml).findall("./dyndnses/dyndns"):
        def raw(tag: str) -> str:
            return d.findtext(tag) or ""

        def flag(tag: str) -> bool:
            el = d.find(tag)
            return el is not None and (el.text or "").strip().lower() not in ("false", "0", "no")

        host, domain = raw("host").strip(), raw("domainname").strip()
        out.append({
            "fqdn": f"{host}.{domain}" if domain and host not in ("", "@") else (domain or host),
            "fingerprint": ddns_fingerprint(raw("interface"), raw("type"), raw("host"), raw("domainname"), raw("descr")),
            "enabled": flag("enable"),
            "type": raw("type").strip(), "interface": raw("interface").strip(), "host": raw("host").strip(),
            "domainname": raw("domainname").strip(), "username": raw("username").strip(),
            "has_password": bool((d.findtext("password") or "").strip()),
            "zoneid": raw("zoneid").strip(), "ttl": raw("ttl").strip(), "mx": raw("mx").strip(),
            "updateurl": raw("updateurl").strip(), "resultmatch": raw("resultmatch").strip(),
            "wildcard": flag("wildcard"), "proxied": flag("proxied"), "verboselog": flag("verboselog"),
            "descr": raw("descr").strip(),
        })
    return out


# Aliases that packages create and maintain themselves (pfBlockerNG's pfB_* lists).
SYSTEM_ALIAS_PREFIXES = ("pfb_",)


def is_system_alias(alias: dict[str, Any]) -> bool:
    return alias["name"].lower().startswith(SYSTEM_ALIAS_PREFIXES) or alias["descr"].lower().startswith("pfblockerng")


def interfaces_from_xml(xml: bytes) -> list[dict[str, str]]:
    """The firewall's interfaces in config order: [{"id": "wan", "name": "WAN"}, {"id": "opt1", "name": "DMZ"}]."""
    root = _parse(xml)
    out = []
    for el in list(root.find("interfaces") if root.find("interfaces") is not None else []):
        out.append({"id": el.tag, "name": (el.findtext("descr") or "").strip() or el.tag.upper()})
    return out


def firewall_rules_from_xml(xml: bytes) -> list[dict[str, Any]]:
    """Firewall > Rules, in the firewall's order. Floating rules have interface "floating" and list theirs."""
    out = []
    for rule in _parse(xml).findall("./filter/rule"):
        def text(tag: str) -> str:
            return (rule.findtext(tag) or "").strip()

        src, src_port = _endpoint(rule.find("source"))
        dst, dst_port = _endpoint(rule.find("destination"))
        floating = text("floating") == "yes"
        descr = text("descr")
        out.append({
            "tab": "floating" if floating else (text("interface") or "wan"),
            "interfaces": [i for i in text("interface").split(",") if i],
            "action": text("type") or "pass",
            "ipprotocol": {"inet": "IPv4", "inet6": "IPv6", "inet46": "IPv4+6"}.get(text("ipprotocol"), text("ipprotocol") or "IPv4"),
            "protocol": text("protocol") or "any",
            "source": src, "source_port": src_port,
            "destination": dst, "destination_port": dst_port,
            "gateway": text("gateway"),
            "schedule": text("sched"),
            "log": rule.find("log") is not None,
            "quick": rule.find("quick") is not None,
            "direction": text("direction"),
            "disabled": rule.find("disabled") is not None,
            "nat": bool(text("associated-rule-id")),
            "managed": bool(text("comsense_policy")) or descr.startswith("[CSFM]"),
            "descr": descr,
        })
    return out


def rule_tabs(interfaces: list[dict[str, str]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Tabs as pfSense shows them: Floating (if used), the interfaces, then rule-only groups (OpenVPN, IPsec...)."""
    counts: dict[str, int] = {}
    for r in rules:
        counts[r["tab"]] = counts.get(r["tab"], 0) + 1
    tabs = [{"id": "floating", "name": "Floating"}] if counts.get("floating") else []
    tabs += interfaces
    known = {t["id"] for t in tabs}
    names = {"openvpn": "OpenVPN", "ipsec": "IPsec", "wireguard": "WireGuard", "enc0": "IPsec"}
    tabs += [{"id": tab, "name": names.get(tab, tab)} for tab in counts if tab not in known]
    return [t | {"count": counts.get(t["id"], 0)} for t in tabs]


def config_summary(settings: Settings, backup: Backup) -> dict[str, Any]:
    """Port forwards and email notification state in a backup (cached; backups never change)."""
    key = (backup.id, backup.sha256)
    if key in _nat_cache:
        _nat_cache.move_to_end(key)
        return _nat_cache[key]
    xml = load_backup(settings, backup)
    interfaces = interfaces_from_xml(xml)
    filter_rules = firewall_rules_from_xml(xml)
    rules = {"nat": port_forwards_from_xml(xml), "aliases": aliases_from_xml(xml),
             "smtp": smtp_notifications_from_xml(xml), "rules": filter_rules,
             "rule_tabs": rule_tabs(interfaces, filter_rules), "interfaces": interfaces,
             "ddns": ddns_from_xml(xml)}
    _nat_cache[key] = rules
    while len(_nat_cache) > _NAT_CACHE_SIZE:
        _nat_cache.popitem(last=False)
    return rules
