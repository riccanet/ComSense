"""Any part of a firewall's configuration, read and edited as structured data: the API and MCP server's general
configuration tools (get_config / edit_config). Read from the firewall's current backup, in the same shape
pfSense's own code sees config.xml (config_get_path), so a path read here is the path an edit names. Edits
are applied by the agent (config_edit, agent tasks.inc) under the change guard.

Package settings, accounts, certificates and the hooks that run commands as root are never edited this way;
the agent refuses them too. Secrets are hidden when read, and an edit that would write a hidden value back is
refused, so a subtree read and sent back unchanged cannot wipe a password.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections import OrderedDict
from typing import Any

from ..config import Settings
from ..models import Backup
from .backups import load_backup
from .configview import SECRET_TAGS, _parse

HIDDEN = "[hidden]"
OPS = ("set", "delete", "append", "insert")
MAX_OPS = 200
MAX_PAYLOAD = 512 * 1024
PATH_RE = re.compile(r"^[A-Za-z0-9_\-][A-Za-z0-9_.\-]*(/[A-Za-z0-9_\-][A-Za-z0-9_.\-]*)*$")
# Never edited here (mirrors CSFM_EDIT_PROTECTED in the agent): settings packages own, accounts and their
# authentication, certificates and keys, commands run as root, and config.xml's own revision.
PROTECTED_RE = re.compile(
    r"^(installedpackages|system/(user|group|authserver|shellcmd|earlyshellcmd|afterfilterchangeshellcmd)"
    r"|cert|ca|crl|cron|revision)(/|$)")
PROTECTED_TEXT = ("package settings (installedpackages), user accounts, groups and authentication servers, "
                  "certificates, cron and shell commands")

# Elements pfSense always reads as lists, even with one item (xmlparse.inc listtags()), so their paths take
# an index: filter/rule/0, dhcpd/lan/staticmap/2.
LIST_TAGS = frozenset("""
acls alias aliasurl allowedip allowedhostname authserver bridged build_port_path ca cacert cert crl clone config
container columnitem depends_on_package disk dnsserver dnsupdate domainoverrides dyndns earlyshellcmd element
encryption-algorithm-option field fieldname hash-algorithm-option gateway_item gateway_group gif gre group hosts
member ifgroupentry igmpentry interface_array item key lagg lb_action lb_pool lb_protocol lb_virtual_server menu
mobilekey monitor_type mount npt ntpserver onetoone openvpn-server openvpn-client openvpn-csc option package
passthrumac phase1 phase2 ppp pppoe priv proxyarpnet queue pages pipe radnsserver roll route row rrddatafile
rule schedule service servernat servers serversdisabled shellcmd staticmap subqueue switch swport timerange
tunnel user vip virtual_server vlan vlangroup voucherdbfile vxlan winsserver wolentry widget xmldatafile
""".split())
_SECRETS = frozenset(t.lower() for t in SECRET_TAGS)

_tree_cache: OrderedDict[tuple[int, str], dict[str, Any]] = OrderedDict()
_TREE_CACHE_SIZE = 16


class ConfigEditError(ValueError):
    pass


def _to_value(el: ET.Element) -> Any:
    children = list(el)
    if not children:
        if el.tag.lower() in _SECRETS and (el.text or "").strip():
            return HIDDEN
        return (el.text or "").strip()
    out: dict[str, Any] = {}
    for child in children:
        value = _to_value(child)
        if child.tag in LIST_TAGS:
            out.setdefault(child.tag, []).append(value)
        elif child.tag in out:
            if not isinstance(out[child.tag], list):
                out[child.tag] = [out[child.tag]]
            out[child.tag].append(value)
        else:
            out[child.tag] = value
    return out


def config_tree(settings: Settings, backup: Backup) -> dict[str, Any]:
    """The whole configuration as nested dicts and lists, secrets hidden (cached; backups never change)."""
    key = (backup.id, backup.sha256)
    if key in _tree_cache:
        _tree_cache.move_to_end(key)
        return _tree_cache[key]
    tree = _to_value(_parse(load_backup(settings, backup)))
    tree = tree if isinstance(tree, dict) else {}
    _tree_cache[key] = tree
    while len(_tree_cache) > _TREE_CACHE_SIZE:
        _tree_cache.popitem(last=False)
    return tree


def lookup(tree: dict[str, Any], path: str) -> tuple[bool, Any]:
    """(found, value) at a config path; list items by index."""
    node: Any = tree
    for part in [p for p in path.split("/") if p]:
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return False, None
    return True, node


def outline(value: Any, depth: int = 1) -> Any:
    """A short view of a big subtree: keys with a count or a value, `depth` levels down."""
    if isinstance(value, list):
        return f"[list of {len(value)}]" if depth <= 0 else [outline(v, depth - 1) for v in value]
    if isinstance(value, dict):
        if depth <= 0:
            return f"{{{len(value)} keys}}"
        return {k: outline(v, depth - 1) for k, v in value.items()}
    return value


def editable(path: str) -> bool:
    return bool(PATH_RE.match(path)) and not PROTECTED_RE.match(path)


def _contains_hidden(value: Any) -> bool:
    if isinstance(value, str):
        return value == HIDDEN
    if isinstance(value, dict):
        return any(_contains_hidden(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_hidden(v) for v in value)
    return False


def _valid_value(value: Any) -> bool:
    """Strings, numbers and booleans (as text), lists and dicts of them, as config.xml can hold."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return True
    if isinstance(value, list):
        return all(_valid_value(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", k) and _valid_value(v)
                   for k, v in value.items())
    return False


def _texts(value: Any) -> Any:
    """Values as config.xml keeps them: text; true as "" (a flag that is present), false/null removed."""
    if isinstance(value, dict):
        return {k: _texts(v) for k, v in value.items() if v is not False and v is not None}
    if isinstance(value, list):
        return [_texts(v) for v in value]
    if value is True:
        return ""
    return str(value)


def validate_ops(ops: Any) -> list[dict[str, Any]]:
    """Check edit operations (raises ConfigEditError); returns them normalised for the agent. Whether each path
    exists is checked on the firewall, in order, since earlier operations can move list items."""
    if not isinstance(ops, list) or not ops:
        raise ConfigEditError("operations must be a non-empty list")
    if len(ops) > MAX_OPS:
        raise ConfigEditError(f"at most {MAX_OPS} operations at once")
    out = []
    for n, op in enumerate(ops, 1):
        if not isinstance(op, dict):
            raise ConfigEditError(f"operation {n} must be an object")
        kind, path = op.get("op"), str(op.get("path") or "").strip("/")
        if kind not in OPS:
            raise ConfigEditError(f"operation {n}: op must be one of {', '.join(OPS)}")
        if not PATH_RE.match(path):
            raise ConfigEditError(f"operation {n}: '{path}' is not a config path (like system/hostname or filter/rule/2)")
        if PROTECTED_RE.match(path):
            raise ConfigEditError(f"operation {n}: '{path}' cannot be edited here ({PROTECTED_TEXT})")
        if kind == "set" and op.get("value") in (False, None) and "value" in op:
            kind = "delete"  # turning a flag off (enable: false) removes it, as pfSense keeps flags
        clean: dict[str, Any] = {"op": kind, "path": path}
        if kind != "delete":
            if "value" not in op:
                raise ConfigEditError(f"operation {n}: '{kind}' needs a value")
            if not _valid_value(op["value"]):
                raise ConfigEditError(f"operation {n}: the value must be text, numbers, true/false, lists and objects")
            if _contains_hidden(op["value"]):
                raise ConfigEditError(f"operation {n}: the value contains '{HIDDEN}', a secret hidden when the "
                                      "configuration was read; give the real value or leave that field out")
            clean["value"] = _texts(op["value"])
        if op.get("expect") is not None:
            if not isinstance(op["expect"], dict) or not _valid_value(op["expect"]):
                raise ConfigEditError(f"operation {n}: expect must be an object of fields the item has now")
            clean["expect"] = _texts(op["expect"])
        out.append(clean)
    if len(json.dumps(out)) > MAX_PAYLOAD:
        raise ConfigEditError("the edit is too large; split it")
    return out
