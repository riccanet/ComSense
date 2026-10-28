"""ARP entries and DHCP leases the firewalls report (agent collect.inc, every few minutes), and finding a
device by MAC address, IP address or hostname across every firewall."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Device, Organization

MAX_ENTRIES = 4000
KINDS = ("arp", "leases", "static")
KIND_LABELS = {"arp": "ARP", "leases": "DHCP lease", "static": "DHCP static mapping"}
_FIELDS = {
    "arp": ("ip", "mac", "if", "iface", "hostname", "permanent", "expires"),
    "leases": ("ip", "mac", "hostname", "starts", "ends", "state", "server"),
    "static": ("ip", "mac", "hostname", "descr", "iface"),
}
_HEX = re.compile(r"[^0-9a-f]")


def clean(report: Any) -> dict[str, list[dict[str, Any]]] | None:
    """The agent's 'neighbors' section, limited to known fields and sizes; None if it is not one."""
    if not isinstance(report, dict):
        return None
    out: dict[str, list[dict[str, Any]]] = {}
    for kind in KINDS:
        rows = report.get(kind)
        out[kind] = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            entry: dict[str, Any] = {}
            for f in _FIELDS[kind]:
                v = row.get(f)
                entry[f] = v if isinstance(v, (bool, int)) or v is None else str(v)[:128]
            out[kind].append(entry)
            if len(out[kind]) >= MAX_ENTRIES:
                break
    return out


def mac_key(value: str) -> str:
    """A MAC address in any notation (a4:f8:ff:c8:67:32, A4-F8-FF-..., a4f8.ffc8.6732) as bare hex digits."""
    return _HEX.sub("", value.lower())


def matches(entry: dict[str, Any], query: str) -> bool:
    q = query.strip().lower()
    if not q:
        return True
    hexq = mac_key(q)
    mac = mac_key(str(entry.get("mac") or ""))
    # A MAC typed in any notation, or part of one (at least 4 hex digits so "10" does not match everything).
    if len(hexq) >= 4 and len(hexq) == len(re.sub(r"[\s:.\-]", "", q)) and hexq in mac:
        return True
    return any(q in str(entry.get(f) or "").lower() for f in ("ip", "hostname", "descr", "iface", "if"))


def device_entries(device: Device, query: str = "") -> dict[str, list[dict[str, Any]]]:
    data = device.neighbors or {}
    return {kind: [e for e in data.get(kind) or [] if isinstance(e, dict) and matches(e, query)] for kind in KINDS}


def by_ip(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Entries in address order (192.168.1.9 before 192.168.1.10); ones without a valid address last."""
    def key(e: dict[str, Any]):
        try:
            return (0, ipaddress.ip_address(str(e.get("ip") or "")))
        except ValueError:
            return (1, ipaddress.ip_address("0.0.0.0"))
    return sorted(entries, key=key)


def search(db: Session, query: str, limit: int = 200) -> list[dict[str, Any]]:
    """Every ARP entry, lease and static mapping on any firewall that matches query, newest data first."""
    if len(query.strip()) < 2:
        return []
    out: list[dict[str, Any]] = []
    stmt = (select(Device).outerjoin(Organization, Device.organization_id == Organization.id)
            .where(Device.neighbors.is_not(None)).order_by(Organization.name, Device.name))
    for device in db.scalars(stmt):
        for kind, entries in device_entries(device, query).items():
            for e in entries:
                out.append({"firewall_id": device.id, "firewall": device.name,
                            "customer": device.organization.name if device.organization else None,
                            "kind": kind, "seen": device.neighbors_at, **e})
                if len(out) >= limit:
                    return out
    return out


def as_api(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**r, "seen": r["seen"].isoformat() if isinstance(r.get("seen"), datetime) else r.get("seen")}
            for r in rows]
