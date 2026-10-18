from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..models import Alert, Device, Task, TaskStatus, TaskType, utcnow

DISK_THRESHOLD = 90.0
MEMORY_THRESHOLD = 90.0
OFFLINE_KEY = "offline"


def _conditions(report: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """Derive {key: (severity, message)} from a check-in report."""
    found: dict[str, tuple[str, str]] = {}
    for gw in report.get("gateways") or []:
        status = str(gw.get("status", "")).lower()
        name = str(gw.get("name", "?"))
        if status in ("down", "force_down"):
            found[f"gateway:{name}"] = ("critical", f"Gateway {name} is down")
        elif status in ("loss", "delay", "highloss", "highdelay"):
            found[f"gateway:{name}"] = (
                "warning",
                f"Gateway {name} reports {status} (loss {gw.get('loss', '?')}, delay {gw.get('delay', '?')})",
            )
    for svc in report.get("services") or []:
        if svc.get("enabled", True) and svc.get("running") is False:
            name = str(svc.get("name", "?"))
            found[f"service:{name}"] = ("warning", f"Service {name} is not running")
    metrics = report.get("metrics") or {}
    disk = metrics.get("disk_pct")
    if isinstance(disk, (int, float)) and disk >= DISK_THRESHOLD:
        found["disk"] = ("warning", f"Disk usage is {disk:.0f}%")
    mem = metrics.get("mem_pct")
    if isinstance(mem, (int, float)) and mem >= MEMORY_THRESHOLD:
        found["memory"] = ("warning", f"Memory usage is {mem:.0f}%")
    return found


ROLLBACK_PREFIX = "rollback:"


def open_alerts(db: Session, device: Device) -> dict[str, Alert]:
    stmt = select(Alert).where(Alert.device_id == device.id, Alert.resolved_at.is_(None))
    return {a.key: a for a in db.scalars(stmt)}


def evaluate_report(db: Session, device: Device, report: dict[str, Any]) -> None:
    current = _conditions(report)
    existing = open_alerts(db, device)
    now = utcnow()
    for key, (severity, message) in current.items():
        alert = existing.get(key)
        if alert is None:
            db.add(Alert(device_id=device.id, key=key, severity=severity, message=message))
        else:
            alert.severity = severity
            alert.message = message
    for key, alert in existing.items():
        # Rollback alerts describe an event, not a condition; they stay open until cleared.
        if key != OFFLINE_KEY and not key.startswith(ROLLBACK_PREFIX) and key not in current:
            alert.resolved_at = now
    offline = existing.get(OFFLINE_KEY)
    if offline is not None:
        offline.resolved_at = now


def raise_offline(db: Session, device: Device) -> None:
    if OFFLINE_KEY in open_alerts(db, device):
        return
    db.add(
        Alert(
            device_id=device.id,
            key=OFFLINE_KEY,
            severity="critical",
            message="Firewall has stopped checking in",
        )
    )


def record_rollbacks(db: Session, device: Device, events: Any) -> int:
    """Handle rollbacks the agent reports: alert, mark the tasks, and stop re-sending the change.

    Each event is {"id", "tasks": [task ids], "changes", "reason", "changed_at", "rolled_back_at"}.
    Events can be reported more than once (a lost response); the alert key makes them idempotent.
    Returns the number of new events. The caller commits.
    """
    if not isinstance(events, list):
        return 0
    new = 0
    rolled = dict(device.rolled_back_policies or {})
    for event in events:
        if not isinstance(event, dict) or not str(event.get("id", "")).strip():
            continue
        key = f"{ROLLBACK_PREFIX}{str(event['id'])[:64]}"
        if db.scalar(select(Alert.id).where(Alert.device_id == device.id, Alert.key == key)):
            continue
        new += 1
        changes = str(event.get("changes", ""))[:500] or "a configuration change"
        reason = str(event.get("reason", ""))[:300]
        when = str(event.get("rolled_back_at", ""))[:40]
        db.add(
            Alert(
                device_id=device.id,
                key=key,
                severity="critical",
                message=f"Change rolled back on the firewall: {changes}. Reason: {reason}.",
            )
        )
        task_ids = [int(t) for t in event.get("tasks") or [] if str(t).isdigit()]
        for task in db.scalars(select(Task).where(Task.device_id == device.id, Task.id.in_(task_ids))):
            task.status = TaskStatus.failed
            task.output = (task.output + "\n\n" if task.output else "") + (
                f"Rolled back on the firewall at {when}: {reason}. The previous configuration was restored."
            )
            task.finished_at = task.finished_at or utcnow()
            if task.type == TaskType.apply_policy:
                policy = (task.payload or {}).get("policy") or {}
                if "id" in policy:
                    rolled[str(policy["id"])] = str(policy.get("hash", ""))
            elif task.type == TaskType.remove_policy:
                rolled[str((task.payload or {}).get("policy_id"))] = "remove"
        audit(db, "system", "device.change_rolled_back", target=device.id, detail=f"{changes}: {reason}")
    device.rolled_back_policies = rolled
    return new
