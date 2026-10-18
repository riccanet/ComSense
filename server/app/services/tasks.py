from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Device, DeviceStatus, Task, TaskStatus, TaskType, aware, utcnow

# Which locally granted capability each task needs. The agent enforces the same
# mapping itself; the server checks it only to give admins an early error.
TASK_CAPABILITY: dict[TaskType, str | None] = {
    TaskType.backup: "backup",
    TaskType.apply_policy: "policy",
    TaskType.remove_policy: "policy",
    TaskType.check_updates: None,
    TaskType.refresh_inventory: None,
    TaskType.upgrade_system: "upgrade",
    TaskType.upgrade_packages: "upgrade",
    TaskType.install_package: "packages",
    TaskType.remove_package: "packages",
    TaskType.restart_service: "services",
    TaskType.restore_backup: "restore",
    TaskType.reboot: "reboot",
    TaskType.update_agent: "upgrade",
}

# How long a task may stay "sent"/"running" without a final result.
TASK_TIMEOUT: dict[TaskType, timedelta] = {
    TaskType.upgrade_system: timedelta(hours=2),
    TaskType.upgrade_packages: timedelta(hours=1),
    TaskType.install_package: timedelta(minutes=30),
    TaskType.remove_package: timedelta(minutes=30),
    TaskType.restore_backup: timedelta(minutes=30),
    TaskType.reboot: timedelta(minutes=30),
    TaskType.update_agent: timedelta(minutes=30),
}
DEFAULT_TASK_TIMEOUT = timedelta(minutes=15)
# Tasks that are not picked up within this window expire, so a box that was offline
# for a week does not suddenly reboot when it comes back.
DEFAULT_PICKUP_WINDOW = timedelta(days=1)

OPEN_STATES = (TaskStatus.pending, TaskStatus.sent, TaskStatus.running)

# Tasks that only read from or copy off the firewall. Everything else changes it
# and is available only with CSFM_ENABLE_FIREWALL_CHANGES.
SAFE_TASKS = frozenset({TaskType.backup, TaskType.check_updates, TaskType.refresh_inventory})
# Updating ComSense's own agent does not change the firewall's configuration, so it is not
# "coming soon"; it still needs the firewall's local upgrade permission.
AGENT_TASKS = frozenset({TaskType.update_agent})
COMING_SOON = "Coming soon: changing firewall settings from ComSense is not available yet."


class TaskError(ValueError):
    pass


def queue_task(
    db: Session,
    device: Device,
    ttype: TaskType,
    payload: dict[str, Any] | None = None,
    actor: str = "system",
    pickup_window: timedelta = DEFAULT_PICKUP_WINDOW,
    changes_enabled: bool = False,
) -> Task:
    if ttype not in SAFE_TASKS and ttype not in AGENT_TASKS and not changes_enabled:
        raise TaskError(COMING_SOON)
    if device.status == DeviceStatus.disabled:
        raise TaskError("Device is disabled")
    if device.status == DeviceStatus.pending:
        raise TaskError("Device is waiting for approval")
    needed = TASK_CAPABILITY[ttype]
    if needed and needed not in (device.capabilities or []):
        raise TaskError(
            f"The firewall does not allow '{needed}' actions. Enable it in "
            "Services > ComSense Agent on the firewall."
        )
    task = Task(
        device_id=device.id,
        type=ttype,
        payload=payload or {},
        created_by=actor,
        not_after=utcnow() + pickup_window,
    )
    db.add(task)
    return task


def has_open_task(db: Session, device: Device, ttype: TaskType) -> bool:
    stmt = select(Task.id).where(
        Task.device_id == device.id, Task.type == ttype, Task.status.in_(OPEN_STATES)
    )
    return db.scalar(stmt.limit(1)) is not None


def take_pending_tasks(db: Session, device: Device, limit: int = 10) -> list[Task]:
    now = utcnow()
    stmt = (
        select(Task)
        .where(Task.device_id == device.id, Task.status == TaskStatus.pending)
        .order_by(Task.id)
    )
    out = []
    for task in db.scalars(stmt):
        if task.not_after is not None and aware(task.not_after) < now:
            task.status = TaskStatus.expired
            task.finished_at = now
            continue
        if len(out) < limit:
            task.status = TaskStatus.sent
            task.sent_at = now
            out.append(task)
    return out


def task_to_wire(task: Task) -> dict[str, Any]:
    return {"id": task.id, "type": task.type.value, "payload": task.payload}


def expire_stale_tasks(db: Session, now: datetime | None = None) -> int:
    now = now or utcnow()
    count = 0
    stmt = select(Task).where(Task.status.in_((TaskStatus.sent, TaskStatus.running)))
    for task in db.scalars(stmt):
        timeout = TASK_TIMEOUT.get(task.type, DEFAULT_TASK_TIMEOUT)
        started = aware(task.sent_at or task.created_at)
        if now - started > timeout:
            task.status = TaskStatus.failed
            task.finished_at = now
            task.output = (task.output + "\n" if task.output else "") + "Timed out waiting for the agent"
            count += 1
    return count
