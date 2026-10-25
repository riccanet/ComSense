"""What the REST API (/api/v1) and the MCP server can do, in one place so both behave alike.

Callers authenticate with an API key (Settings > API keys), which carries a role: viewer keys read,
operator and admin keys may also queue tasks, acknowledge alerts and move firewalls between customers.
Everything returns plain JSON-able data; problems raise ApiError with an HTTP status.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings
from ..models import (
    Alert,
    ApiKey,
    Backup,
    Device,
    DeviceStatus,
    Organization,
    Policy,
    Role,
    Task,
    TaskType,
    aware,
    utcnow,
)
from ..security import hash_secret
from .agentpkg import agent_outdated, latest_package
from .alerts import category_of
from .tasks import TaskError, queue_task

KEY_PREFIX = "csfm_api_"
ROLE_RANK = {Role.viewer: 0, Role.operator: 1, Role.admin: 2}
# Tasks a key may queue: name -> (task type, label). check_now is a refresh that wakes the firewall.
RUNNABLE = {
    "check_now": (TaskType.refresh_inventory, "Check now"),
    "backup": (TaskType.backup, "Back up the configuration"),
    "check_updates": (TaskType.check_updates, "Check for pfSense updates"),
    "update_agent": (TaskType.update_agent, "Update the ComSense agent"),
    "upgrade_packages": (TaskType.upgrade_packages, "Upgrade all packages"),
    "upgrade_system": (TaskType.upgrade_system, "Upgrade pfSense (reboots)"),
    "reboot": (TaskType.reboot, "Reboot"),
    "restart_service": (TaskType.restart_service, "Restart a service (needs service)"),
    "install_package": (TaskType.install_package, "Install a package (needs package)"),
    "remove_package": (TaskType.remove_package, "Remove a package (needs package)"),
    "free_disk_space": (TaskType.free_disk_space, "Clear the package cache and old logs"),
}


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Principal:
    key_id: int
    name: str
    role: Role

    @property
    def actor(self) -> str:
        return f"api:{self.name}"[:64]

    def require(self, role: Role) -> None:
        if ROLE_RANK[self.role] < ROLE_RANK[role]:
            raise ApiError(403, f"This API key's role ({self.role.value}) cannot do this; it needs {role.value}")


# ---------------------------------------------------------------------------- keys


def new_key_value() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def create_key(db: Session, name: str, role: Role, created_by: str, expires_days: int | None) -> tuple[ApiKey, str]:
    """A new key and its value, which is shown once and stored only as a hash. The caller commits."""
    if role not in ROLE_RANK:
        raise ApiError(400, "Unknown role")
    value = new_key_value()
    key = ApiKey(name=name.strip()[:128] or "API key", prefix=value[: len(KEY_PREFIX) + 6], key_hash=hash_secret(value),
                 role=role, created_by=created_by,
                 expires_at=utcnow() + timedelta(days=expires_days) if expires_days else None)
    db.add(key)
    return key, value


def authenticate(db: Session, authorization: str, ip: str = "") -> Principal | None:
    """The principal for an "Authorization: Bearer csfm_api_..." header, or None."""
    scheme, _, token = (authorization or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token.startswith(KEY_PREFIX):
        return None
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_secret(token)))
    if key is None or not key.usable():
        return None
    now = utcnow()
    if key.last_used_at is None or now - aware(key.last_used_at) > timedelta(minutes=1) or key.last_used_ip != ip:
        key.last_used_at, key.last_used_ip = now, ip[:64]
        db.commit()
    return Principal(key.id, key.name, key.role)


# ---------------------------------------------------------------------------- reading


def _iso(value) -> str | None:
    return aware(value).isoformat() if value is not None else None


def _wan_ips(device: Device) -> list[str]:
    from ..api.agent import wan_addresses  # noqa: PLC0415 - the agent API module imports this one's siblings

    return wan_addresses((device.inventory or {}).get("interfaces") or []) or ([device.wan_ip] if device.wan_ip else [])


def firewall_summary(device: Device, latest_agent: str = "", open_alerts: int = 0) -> dict[str, Any]:
    updates = device.updates or {}
    return {
        "id": device.id,
        "name": device.name,
        "hostname": device.hostname,
        "customer": {"id": device.organization.id, "name": device.organization.name} if device.organization else None,
        "status": device.status.value,
        "edition": device.edition,
        "pfsense_version": device.product_version,
        "agent_version": device.agent_version,
        "agent_update_available": bool(latest_agent and device.agent_version
                                       and agent_outdated(device.agent_version, latest_agent)),
        "wan_ips": _wan_ips(device),
        "last_seen": _iso(device.last_seen_at),
        "last_backup": _iso(device.last_backup_at),
        "open_alerts": open_alerts,
        "pfsense_update_available": bool(updates.get("update_available")),
        "pfsense_update_version": updates.get("version") if updates.get("update_available") else None,
    }


def _latest_agent(settings: Settings) -> str:
    package = latest_package(settings.data_dir / "downloads")
    return package["version"] if package else ""


def _open_alert_counts(db: Session) -> dict[str, int]:
    return dict(db.execute(select(Alert.device_id, func.count()).where(Alert.resolved_at.is_(None))
                           .group_by(Alert.device_id)).all())


def _device(db: Session, firewall_id: str) -> Device:
    device = db.get(Device, str(firewall_id))
    if device is None:
        raise ApiError(404, "No firewall with that id")
    return device


def list_firewalls(db: Session, settings: Settings, customer_id: int | None = None, status: str | None = None,
                   search: str | None = None, agent_outdated_only: bool = False) -> list[dict[str, Any]]:
    stmt = (select(Device).outerjoin(Organization, Device.organization_id == Organization.id)
            .order_by(Organization.name.is_(None), func.lower(Organization.name), func.lower(Device.name)))
    if customer_id is not None:
        stmt = stmt.where(Device.organization_id == customer_id)
    if status:
        if status not in DeviceStatus.__members__:
            raise ApiError(400, f"status must be one of {sorted(DeviceStatus.__members__)}")
        stmt = stmt.where(Device.status == DeviceStatus(status))
    if search:
        like = f"%{search}%"
        stmt = stmt.where(Device.name.ilike(like) | Device.hostname.ilike(like) | Device.wan_ip.ilike(like))
    latest, counts = _latest_agent(settings), _open_alert_counts(db)
    out = [firewall_summary(d, latest, counts.get(d.id, 0)) for d in db.scalars(stmt)]
    return [f for f in out if f["agent_update_available"]] if agent_outdated_only else out


def get_firewall(db: Session, settings: Settings, firewall_id: str) -> dict[str, Any]:
    device = _device(db, firewall_id)
    inv = device.inventory or {}
    detail = firewall_summary(device, _latest_agent(settings), _open_alert_counts(db).get(device.id, 0))
    detail.update(
        serial=device.serial,
        platform=device.platform,
        arch=device.arch,
        enrolled=_iso(device.enrolled_at),
        notes=device.notes,
        capabilities=list(device.capabilities or []),
        metrics=inv.get("metrics") or {},
        interfaces=[{k: i.get(k) for k in ("name", "descr", "if", "status", "ipaddr", "subnet", "gateway")}
                    for i in inv.get("interfaces") or [] if isinstance(i, dict)],
        gateways=inv.get("gateways") or [],
        services=inv.get("services") or [],
        packages=inv.get("packages") or [],
        pfsense_updates=device.updates or {},
    )
    return detail


def list_customers(db: Session) -> list[dict[str, Any]]:
    counts = dict(db.execute(select(Device.organization_id, func.count()).group_by(Device.organization_id)).all())
    return [{"id": o.id, "name": o.name, "contact_name": o.contact_name, "contact_email": o.contact_email,
             "contact_phone": o.contact_phone, "firewalls": counts.get(o.id, 0)}
            for o in db.scalars(select(Organization).order_by(func.lower(Organization.name)))]


def get_customer(db: Session, settings: Settings, customer_id: int) -> dict[str, Any]:
    org = db.get(Organization, customer_id)
    if org is None:
        raise ApiError(404, "No customer with that id")
    return {"id": org.id, "name": org.name, "contact_name": org.contact_name, "contact_email": org.contact_email,
            "contact_phone": org.contact_phone, "notes": org.notes,
            "firewalls": list_firewalls(db, settings, customer_id=org.id)}


def _alert(a: Alert) -> dict[str, Any]:
    return {"id": a.id, "firewall_id": a.device_id, "firewall": a.device.name if a.device else "",
            "severity": a.severity, "message": a.message, "opened": _iso(a.opened_at),
            "resolved": _iso(a.resolved_at), "acknowledged_by": a.acknowledged_by or None,
            "category": category_of(a.key)}


def list_alerts(db: Session, open_only: bool = True, firewall_id: str | None = None,
                limit: int = 200) -> list[dict[str, Any]]:
    stmt = select(Alert).order_by(Alert.opened_at.desc()).limit(max(1, min(limit, 1000)))
    if open_only:
        stmt = stmt.where(Alert.resolved_at.is_(None))
    if firewall_id:
        stmt = stmt.where(Alert.device_id == str(firewall_id))
    return [_alert(a) for a in db.scalars(stmt)]


def _task(t: Task) -> dict[str, Any]:
    return {"id": t.id, "firewall_id": t.device_id, "type": t.type.value, "status": t.status.value,
            "payload": {k: v for k, v in (t.payload or {}).items() if k not in ("sha256",)},
            "created_by": t.created_by, "created": _iso(t.created_at), "finished": _iso(t.finished_at),
            "output": t.output}


def list_tasks(db: Session, firewall_id: str, limit: int = 50) -> list[dict[str, Any]]:
    _device(db, firewall_id)
    return [_task(t) for t in db.scalars(select(Task).where(Task.device_id == str(firewall_id))
                                          .order_by(Task.id.desc()).limit(max(1, min(limit, 500))))]


def get_task(db: Session, task_id: int) -> dict[str, Any]:
    task = db.get(Task, task_id)
    if task is None:
        raise ApiError(404, "No task with that id")
    return _task(task)


def list_backups(db: Session, firewall_id: str) -> list[dict[str, Any]]:
    _device(db, firewall_id)
    return [{"id": b.id, "created": _iso(b.created_at), "reason": b.reason, "size": b.size, "sha256": b.sha256,
             "pfsense_version": b.product_version, "config_revision": b.config_revision, "pinned": b.pinned}
            for b in db.scalars(select(Backup).where(Backup.device_id == str(firewall_id))
                                .order_by(Backup.created_at.desc()))]


def list_configurations(db: Session) -> list[dict[str, Any]]:
    return [{"id": p.id, "name": p.name, "type": p.type.value, "revision": p.revision, "enabled": p.enabled,
             "description": p.description} for p in db.scalars(select(Policy).order_by(func.lower(Policy.name)))]


# ---------------------------------------------------------------------------- changes


def run_task(db: Session, settings: Settings, who: Principal, firewall_id: str, task: str,
             package: str = "", service: str = "", ip: str = "") -> dict[str, Any]:
    """Queue a task on a firewall, with the same checks as the console (firewall permissions, the
    firewall-changes switch)."""
    who.require(Role.operator)
    if task not in RUNNABLE:
        raise ApiError(400, f"task must be one of {sorted(RUNNABLE)}")
    device = _device(db, firewall_id)
    ttype = RUNNABLE[task][0]
    payload: dict[str, Any] = {}
    if ttype in (TaskType.install_package, TaskType.remove_package):
        package = package.strip()
        if not package.startswith("pfSense-pkg-"):
            raise ApiError(400, "package must be a pfSense package name (pfSense-pkg-...)")
        if ttype == TaskType.remove_package and package == "pfSense-pkg-ComSense":
            raise ApiError(400, "The ComSense agent cannot remove itself")
        payload["package"] = package
    elif ttype == TaskType.restart_service:
        if not service.strip():
            raise ApiError(400, "service is required")
        payload["service"] = service.strip()
    try:
        if task == "check_now":
            from .bulk import check_now as _check_now  # noqa: PLC0415 - shared with the console

            queued = _check_now(db, device, who.actor)
        elif task == "update_agent":
            from .bulk import update_agent as _update_agent  # noqa: PLC0415

            downloads: Path = settings.data_dir / "downloads"
            latest = latest_package(downloads)
            if latest is None:
                raise ApiError(409, "This server has no agent package to send")
            queued = _update_agent(db, device, who.actor, latest, downloads)
        else:
            queued = queue_task(db, device, ttype, payload, actor=who.actor,
                                changes_enabled=settings.enable_firewall_changes)
    except TaskError as exc:
        raise ApiError(409, str(exc)) from exc
    db.flush()
    audit(db, who.actor, f"task.{ttype.value}", target=device.id, detail=f"via API {payload or ''}".strip(), ip=ip)
    db.commit()
    return _task(queued)


def acknowledge_alert(db: Session, who: Principal, alert_id: int, ip: str = "") -> dict[str, Any]:
    who.require(Role.operator)
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise ApiError(404, "No alert with that id")
    alert.acknowledged_by = who.actor
    audit(db, who.actor, "alert.acknowledged", target=alert.device_id, detail=alert.message[:200], ip=ip)
    db.commit()
    return _alert(alert)


def set_customer(db: Session, who: Principal, firewall_id: str, customer_id: int | None, ip: str = "") -> dict[str, Any]:
    who.require(Role.operator)
    device = _device(db, firewall_id)
    org = None
    if customer_id is not None:
        org = db.get(Organization, customer_id)
        if org is None:
            raise ApiError(404, "No customer with that id")
    device.organization_id = org.id if org else None
    audit(db, who.actor, "device.assigned", target=device.id, detail=org.name if org else "no customer", ip=ip)
    db.commit()
    db.refresh(device)
    return firewall_summary(device)

