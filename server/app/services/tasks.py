from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Device, DeviceStatus, Task, TaskStatus, TaskType, aware, utcnow
from .backups import PRE_UPGRADE_REASON

# Which locally granted capability each task needs. The agent enforces the same
# mapping itself; the server checks it only to give admins an early error.
TASK_CAPABILITY: dict[TaskType, str | None] = {
    TaskType.backup: "backup",
    TaskType.apply_policy: "policy",
    TaskType.remove_policy: "policy",
    TaskType.check_updates: None,
    TaskType.refresh_inventory: None,
    TaskType.read_logs: None,  # read only
    TaskType.free_disk_space: "upgrade",
    TaskType.be_destroy: "upgrade",
    TaskType.upgrade_system: "upgrade",
    TaskType.upgrade_packages: "upgrade",
    TaskType.install_package: "packages",
    TaskType.remove_package: "packages",
    TaskType.restart_service: "services",
    TaskType.restore_backup: "restore",
    TaskType.reboot: "reboot",
    TaskType.update_agent: "upgrade",
    TaskType.open_terminal: "shell",
    TaskType.nat_add: "policy",
    TaskType.nat_remove: "policy",
    TaskType.nat_edit: "policy",
    TaskType.alias_add: "policy",
    TaskType.alias_edit: "policy",
    TaskType.alias_remove: "policy",
    TaskType.ddns_add: "policy",
    TaskType.ddns_edit: "policy",
    TaskType.ddns_remove: "policy",
    TaskType.update_branch: "upgrade",
    TaskType.notifications: "policy",
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
    TaskType.open_terminal: timedelta(minutes=5),
}
DEFAULT_TASK_TIMEOUT = timedelta(minutes=15)
# Tasks that are not picked up within this window expire, so a box that was offline
# for a week does not suddenly reboot when it comes back.
DEFAULT_PICKUP_WINDOW = timedelta(days=1)

OPEN_STATES = (TaskStatus.pending, TaskStatus.sent, TaskStatus.running)

# Tasks that only read from or copy off the firewall. Everything else changes it
# and is available only with CSFM_ENABLE_FIREWALL_CHANGES.
# free_disk_space removes only pkg's download cache and rotated logs, never configuration.
SAFE_TASKS = frozenset({TaskType.backup, TaskType.check_updates, TaskType.refresh_inventory, TaskType.read_logs,
                        TaskType.free_disk_space})
# Updating ComSense's own agent does not change the firewall's configuration, so it is not
# "coming soon"; it still needs the firewall's local upgrade permission.
AGENT_TASKS = frozenset({TaskType.update_agent})
# The remote terminal is its own opt-in on each firewall (the "shell" permission), and every session
# is approved with the admin's authenticator code (web/terminal_routes.py).
TERMINAL_TASKS = frozenset({TaskType.open_terminal})
COMING_SOON = "Coming soon: changing firewall settings from ComSense is not available yet."


class TaskError(ValueError):
    pass


# What the firewall's page calls each task while it runs.
TASK_TITLES = {
    TaskType.backup: "Backing up the configuration",
    TaskType.apply_policy: "Applying a configuration",
    TaskType.remove_policy: "Removing a configuration",
    TaskType.check_updates: "Checking for updates",
    TaskType.upgrade_system: "Upgrading pfSense",
    TaskType.install_package: "Installing a package",
    TaskType.remove_package: "Removing a package",
    TaskType.upgrade_packages: "Upgrading packages",
    TaskType.restart_service: "Restarting a service",
    TaskType.restore_backup: "Restoring a configuration backup",
    TaskType.reboot: "Rebooting",
    TaskType.refresh_inventory: "Checking in",
    TaskType.read_logs: "Reading logs",
    TaskType.free_disk_space: "Freeing disk space",
    TaskType.be_destroy: "Removing a boot environment",
    TaskType.update_agent: "Updating the ComSense agent",
    TaskType.open_terminal: "Opening a terminal",
    TaskType.nat_add: "Adding a port forward",
    TaskType.nat_remove: "Removing a port forward",
    TaskType.nat_edit: "Changing a port forward",
    TaskType.alias_add: "Adding an alias",
    TaskType.alias_edit: "Changing an alias",
    TaskType.alias_remove: "Removing an alias",
    TaskType.ddns_add: "Adding a dynamic DNS entry",
    TaskType.ddns_edit: "Changing a dynamic DNS entry",
    TaskType.ddns_remove: "Removing a dynamic DNS entry",
    TaskType.update_branch: "Switching the update branch",
    TaskType.notifications: "Changing email notifications",
}


def task_title(task: Task) -> str:
    title = TASK_TITLES.get(task.type, task.type.value.replace("_", " ").capitalize())
    detail = task.payload.get("package") or task.payload.get("service") or task.payload.get("version") or ""
    if task.type == TaskType.apply_policy:
        detail = (task.payload.get("policy") or {}).get("name", "")
    return f"{title} ({detail})" if detail and isinstance(detail, str) else title


def task_progress(task: Task) -> dict[str, Any] | None:
    """{percent, step} the agent reports while a long task (a pfSense upgrade) runs, else None."""
    progress = (task.result or {}).get("progress") if task.status == TaskStatus.running else None
    if not isinstance(progress, dict) or not isinstance(progress.get("percent"), (int, float)):
        return None
    return {"percent": max(0, min(100, int(progress["percent"]))), "step": str(progress.get("step", ""))[:120]}


_UNSTABLE = re.compile(r"devel|snapshot|beta|\brc\b|nightly|testing", re.I)
_VERSION = re.compile(r"(\d+)[._](\d+)(?:[._](\d+))?")


def latest_stable_branch(update_branch: Any) -> str | None:
    """The newest stable update branch a firewall offers (from its check-in's update_branch), by the
    version in its description or name; development and snapshot branches never. Without versions to
    compare, the branch pfSense marks as default. None if the firewall reported no branches."""
    branches = (update_branch or {}).get("branches") if isinstance(update_branch, dict) else None
    if not isinstance(branches, list):
        return None
    best: tuple[tuple[int, ...], str] | None = None
    for b in branches:
        if not isinstance(b, dict) or not b.get("name"):
            continue
        text = f"{b.get('descr', '')} {b['name']}"
        if _UNSTABLE.search(text):
            continue
        m = _VERSION.search(str(b.get("descr", ""))) or _VERSION.search(str(b["name"]))
        if m:
            version = tuple(int(x) for x in m.groups(default="0"))
            if best is None or version > best[0]:
                best = (version, str(b["name"]))
    if best is not None:
        return best[1]
    default = next((b for b in branches if isinstance(b, dict) and b.get("default") and b.get("name")), None)
    return str(default["name"]) if default else None


# Free space an upgrade needs (the agent checks too, authoritatively, right before it starts; see tasks.inc).
MIN_FREE_SPACE = {TaskType.upgrade_system: 2 * 1024**3, TaskType.upgrade_packages: 512 * 1024**2}


def _gb(n: float) -> str:
    return f"{n / 1024**3:.1f} GB" if n >= 1024**3 else f"{n / 1024**2:.0f} MB"


def _check_free_space(device: Device, ttype: TaskType) -> None:
    """Refuse an upgrade up front when the firewall's last check-in reported too little free space.
    The agent clears its package cache before giving up, so the cache is allowed for: up to 1 GB."""
    metrics = (device.inventory or {}).get("metrics") or {}
    free = metrics.get("disk_free")
    if not isinstance(free, (int, float)) or isinstance(free, bool):
        return  # agents before 0.2.17 do not report it; the agent's own check still applies
    total = metrics.get("disk_total")
    if isinstance(total, (int, float)) and total < 0:
        return  # wrapped around by a 32-bit agent before 0.2.20, so free is wrong too; the agent's check applies
    needed = MIN_FREE_SPACE[ttype]
    if free + 1024**3 < needed:
        raise TaskError(
            f"Not enough free disk space on the firewall: {_gb(free)} free, {_gb(needed)} needed for this upgrade. "
            "Run \"Free disk space\" from its page and remove old boot environments (its Configuration page) first."
        )


# Upgrades are preceded by a backup of the configuration (pinned when stored, see backups.py).
BACKUP_BEFORE = {TaskType.upgrade_system, TaskType.upgrade_packages}


def queue_task(
    db: Session,
    device: Device,
    ttype: TaskType,
    payload: dict[str, Any] | None = None,
    actor: str = "system",
    pickup_window: timedelta = DEFAULT_PICKUP_WINDOW,
    changes_enabled: bool = False,
) -> Task:
    if ttype not in SAFE_TASKS | AGENT_TASKS | TERMINAL_TASKS and not changes_enabled:
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
    if ttype in MIN_FREE_SPACE:
        _check_free_space(device, ttype)
    if ttype in BACKUP_BEFORE and "backup" in (device.capabilities or []) and not _pre_upgrade_backup_queued(db, device):
        # The configuration as it is before the upgrade, kept (pinned) to roll back to. Queued first,
        # so the firewall uploads it before it starts upgrading (tasks run in the order queued).
        db.add(Task(device_id=device.id, type=TaskType.backup, payload={"reason": PRE_UPGRADE_REASON},
                    created_by=actor, not_after=utcnow() + pickup_window))
        db.flush()
    task = Task(
        device_id=device.id,
        type=ttype,
        payload=payload or {},
        created_by=actor,
        not_after=utcnow() + pickup_window,
    )
    db.add(task)
    return task


def _pre_upgrade_backup_queued(db: Session, device: Device) -> bool:
    stmt = select(Task).where(Task.device_id == device.id, Task.type == TaskType.backup,
                              Task.status == TaskStatus.pending)
    return any((t.payload or {}).get("reason") == PRE_UPGRADE_REASON for t in db.scalars(stmt))


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
