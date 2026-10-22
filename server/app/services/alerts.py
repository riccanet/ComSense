from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..models import Alert, Device, DeviceStatus, Metric, Task, TaskStatus, TaskType, aware, utcnow
from .appsettings import AlertCategorySettings, get_alert_category_settings

OFFLINE_KEY = "offline"
ROLLBACK_PREFIX = "rollback:"
STALLED_PREFIX = "upgrade_stalled:"
# An upgrade whose progress has not moved for this long, while the firewall still checks in, is stuck.
UPGRADE_STALL = timedelta(minutes=20)
# CPU must be high on this many check-ins in a row (about five minutes), so short spikes do not alert.
CPU_SAMPLES = 5

# Alert categories (Settings > Alert categories): key -> (name, what raises it).
CATEGORIES = {
    "system": ("System alerts", "Configuration changes rolled back on the firewall; an upgrade that stopped making progress"),
    "wan": ("WAN connectivity", "A gateway is down or has packet loss or high latency"),
    "down": ("Firewall down", "The firewall stopped checking in"),
    "services": ("Services not running", "An enabled service on the firewall is stopped"),
    "resources": ("High resources", "Disk, memory, CPU or state table usage above its threshold"),
}
RESOURCE_KEYS = ("disk", "memory", "cpu", "states")


def category_of(key: str) -> str:
    if key == OFFLINE_KEY:
        return "down"
    if key.startswith("gateway:"):
        return "wan"
    if key.startswith("service:"):
        return "services"
    if key in RESOURCE_KEYS:
        return "resources"
    return "system"


def category_filter(category: str):
    """SQL condition matching the alert keys of one category (the inverse of category_of)."""
    by_category = {
        "down": Alert.key == OFFLINE_KEY,
        "wan": Alert.key.like("gateway:%"),
        "services": Alert.key.like("service:%"),
        "resources": Alert.key.in_(RESOURCE_KEYS),
    }
    if category in by_category:
        return by_category[category]
    return ~or_(*by_category.values())


def _conditions(report: dict[str, Any], cfg: AlertCategorySettings,
                cpu_history: list[float | None]) -> dict[str, tuple[str, str]]:
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
    if _number(disk) and disk >= cfg.disk_pct:
        found["disk"] = ("warning", f"Disk usage is {disk:.0f}%")
    mem = metrics.get("mem_pct")
    if _number(mem) and mem >= cfg.memory_pct:
        found["memory"] = ("warning", f"Memory usage is {mem:.0f}%")
    if len(cpu_history) >= CPU_SAMPLES and all(_number(c) and c >= cfg.cpu_pct for c in cpu_history):
        found["cpu"] = ("warning", f"CPU usage has been {min(cpu_history):.0f}% or more for {CPU_SAMPLES} check-ins")
    states, states_max = metrics.get("states"), metrics.get("states_max")
    if _number(states) and _number(states_max) and states_max > 0 and 100 * states / states_max >= cfg.states_pct:
        found["states"] = ("warning", f"State table is {100 * states / states_max:.0f}% full ({states} of {states_max})")
    return {k: v for k, v in found.items() if cfg.flag(category_of(k), "enabled")}


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _cpu_history(db: Session, device: Device) -> list[float | None]:
    """CPU usage of the last CPU_SAMPLES check-ins, newest first (including the one being handled)."""
    stmt = select(Metric.cpu_pct).where(Metric.device_id == device.id).order_by(Metric.ts.desc(), Metric.id.desc())
    return list(db.scalars(stmt.limit(CPU_SAMPLES)))


def open_alerts(db: Session, device: Device) -> dict[str, Alert]:
    stmt = select(Alert).where(Alert.device_id == device.id, Alert.resolved_at.is_(None))
    return {a.key: a for a in db.scalars(stmt)}


def evaluate_report(db: Session, device: Device, report: dict[str, Any]) -> None:
    current = _conditions(report, get_alert_category_settings(db), _cpu_history(db, device))
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
        # Rollback and stalled-upgrade alerts are not about the report; they are cleared elsewhere.
        if key != OFFLINE_KEY and not key.startswith((ROLLBACK_PREFIX, STALLED_PREFIX)) and key not in current:
            alert.resolved_at = now
    offline = existing.get(OFFLINE_KEY)
    if offline is not None:
        offline.resolved_at = now


def raise_offline(db: Session, device: Device) -> None:
    if not get_alert_category_settings(db).flag("down", "enabled") or OFFLINE_KEY in open_alerts(db, device):
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
    # With system alerts off the alert is still recorded (it makes events idempotent), already resolved.
    alerting = get_alert_category_settings(db).flag("system", "enabled")
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
                resolved_at=None if alerting else utcnow(),
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


def check_stalled_upgrades(db: Session, now: datetime | None = None) -> None:
    """Alert when a pfSense upgrade stops making progress while the firewall still checks in (a full disk,
    a download that hangs); clear the alert once it moves again or ends. Called by the scheduler."""
    now = now or utcnow()
    alerting = get_alert_category_settings(db).flag("system", "enabled")
    running = {t.id: t for t in db.scalars(select(Task).where(
        Task.type == TaskType.upgrade_system, Task.status == TaskStatus.running))}
    stalled: set[int] = set()
    for task in running.values():
        progress = (task.result or {}).get("progress") or {}
        try:
            last = datetime.fromisoformat((task.result or {})["progress_at"])
        except (KeyError, TypeError, ValueError):
            last = task.sent_at or task.created_at
        if task.device.status != DeviceStatus.online or now - aware(last) < UPGRADE_STALL:
            continue  # offline mid-upgrade is a reboot ("Firewall down" covers a long one)
        stalled.add(task.id)
        key = f"{STALLED_PREFIX}{task.id}"
        if not alerting or db.scalar(select(Alert.id).where(Alert.key == key, Alert.resolved_at.is_(None))):
            continue
        minutes = int((now - aware(last)).total_seconds() // 60)
        step = progress.get("step") or "starting"
        db.add(Alert(device_id=task.device_id, key=key, severity="critical", message=(
            f"pfSense upgrade has made no progress for {minutes} minutes (last step: {step}). "
            "A full disk or a stuck download are the usual causes; check the firewall before rebooting it.")))
    for alert in db.scalars(select(Alert).where(Alert.key.like(f"{STALLED_PREFIX}%"), Alert.resolved_at.is_(None))):
        task_id = alert.key[len(STALLED_PREFIX):]
        if not task_id.isdigit() or int(task_id) not in stalled:
            alert.resolved_at = now
