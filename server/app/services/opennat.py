"""Port forwards open to anyone (source "any"), across the fleet, and limiting them to a pfBlocker GeoIP alias
(pfB_NAmerica_v4: only North American, by default only US, addresses reach them). Read from each firewall's
newest configuration backup; the change itself is the usual port forward edit (nat_edit), which also updates
the port forward's linked filter rule, under the change guard.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Device, Organization
from .configview import config_summary, current_backup

DEFAULT_ALIAS = "pfB_NAmerica_v4"


def open_port_forwards(db: Session, settings: Settings, alias: str = DEFAULT_ALIAS) -> list[dict[str, Any]]:
    """Every enabled port forward whose source is any, by customer and firewall, with whether that firewall
    has `alias` (from pfBlockerNG) to limit it with."""
    out: list[dict[str, Any]] = []
    devices = db.scalars(select(Device).outerjoin(Organization, Device.organization_id == Organization.id)
                         .order_by(Organization.name.is_(None), Organization.name, Device.name))
    for device in devices:
        backup = current_backup(db, device)
        if backup is None:
            continue
        try:
            summary = config_summary(settings, backup)
        except Exception:  # an unreadable backup: that firewall is just left out
            continue
        names = {i["id"]: i["name"] for i in summary.get("interfaces") or []}
        aliases = {a.get("name") for a in summary.get("aliases") or []}
        for r in summary.get("nat") or []:
            if r["disabled"] or r["managed"] or r["src"] not in ("any", ""):
                continue
            out.append({
                "device": device, "id": r["fingerprint"],
                "interface": ", ".join(names.get(i, i) for i in r["interface"].split(",") if i),
                "protocol": r["protocol"], "destination": r["destination"], "port": r["port"],
                "target": r["target"], "local_port": r["local_port"], "descr": r["descr"],
                "alias_ready": alias in aliases,
            })
    return out
