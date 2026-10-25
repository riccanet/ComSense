"""Actions run on many firewalls at once: from the Firewalls page now, or later by a scheduled job.

Each action decides per firewall whether there is anything to do (an upgrade only where the firewall
reported one), so a job can be run on a whole fleet and repeated safely.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Device, Organization, Task, TaskStatus, TaskType
from .agentpkg import agent_outdated, latest_package, package_for
from .tasks import DEFAULT_PICKUP_WINDOW, TaskError, has_open_task, latest_stable_branch, queue_task

# Value of the Run Task select -> label. Order is the order shown.
BULK_ACTIONS = {
    "check_now": "Check now",
    TaskType.backup.value: "Back up configuration now",
    TaskType.check_updates.value: "Check for updates",
    TaskType.update_agent.value: "Update agent",
    TaskType.upgrade_packages.value: "Upgrade packages (where updates are available)",
    TaskType.upgrade_system.value: "Upgrade pfSense (reboots; where an update is available)",
    "latest_branch": "Set update branch to latest stable",
}
# Actions that change the firewall, offered only with CSFM_ENABLE_FIREWALL_CHANGES.
CHANGE_ACTIONS = frozenset({TaskType.upgrade_packages.value, TaskType.upgrade_system.value, "latest_branch"})

# Why a firewall was left out, as the summary words it ("3 already up to date").
UP_TO_DATE = "already up to date"
NOT_REPORTED = "have not reported their update status"
BUSY = "already running it"


def available_actions(settings: Settings) -> dict[str, str]:
    return {k: v for k, v in BULK_ACTIONS.items() if settings.enable_firewall_changes or k not in CHANGE_ACTIONS}


@dataclass
class BulkResult:
    queued: list[str] = field(default_factory=list)  # firewall names
    skipped: dict[str, list[str]] = field(default_factory=dict)  # reason -> firewall names
    refused: list[str] = field(default_factory=list)  # "name: why"

    def skip(self, reason: str, device: Device) -> None:
        self.skipped.setdefault(reason, []).append(device.name)

    def summary(self, label: str) -> str:
        parts = [f"queued on {len(self.queued)} firewall(s)"]
        parts += [f"{len(names)} {reason}" for reason, names in self.skipped.items()]
        if self.refused:
            parts.append(f"{len(self.refused)} refused ({'; '.join(self.refused[:5])}"
                         f"{'; …' if len(self.refused) > 5 else ''})")
        return f"{label}: " + "; ".join(parts) + "."

    def as_dict(self, label: str) -> dict[str, Any]:
        return {"queued": self.queued, "skipped": self.skipped, "refused": self.refused,
                "summary": self.summary(label)}


def check_now(db: Session, device: Device, actor: str) -> Task:
    """Queue a full refresh; a firewall waiting on the agent API (long poll) picks it up at once."""
    existing = db.scalar(
        select(Task).where(
            Task.device_id == device.id, Task.type == TaskType.refresh_inventory, Task.status == TaskStatus.pending
        )
    )
    return existing or queue_task(db, device, TaskType.refresh_inventory, actor=actor)


def update_agent(db: Session, device: Device, actor: str, package: dict[str, str], downloads: Path,
                 pickup_window: timedelta = DEFAULT_PICKUP_WINDOW) -> Task:
    if not agent_outdated(device.agent_version, package["version"]):
        raise TaskError(f"Agent {device.agent_version or '?'} is already current")
    # Agents up to 0.2.9 cannot replace themselves; they get the bootstrap package (services/agentpkg.py).
    package = package_for(downloads, package, device.agent_version)
    payload = {"version": package["version"], "file": package["name"], "sha256": package["sha256"]}
    return queue_task(db, device, TaskType.update_agent, payload, actor=actor, pickup_window=pickup_window)


def _pending_update(device: Device, action: str) -> bool | None:
    """Whether the firewall's last update check found something for this upgrade; None if it never said."""
    updates = device.updates or {}
    if action == TaskType.upgrade_system.value:
        flag = updates.get("update_available")
        return flag if isinstance(flag, bool) else None
    packages = updates.get("packages")
    return bool(packages) if isinstance(packages, list) else None


def target_devices(db: Session, device_ids: list[str] | None) -> list[Device]:
    """The firewalls a job runs on: the listed ones that still exist, or every firewall (None)."""
    stmt = (select(Device).outerjoin(Organization, Device.organization_id == Organization.id)
            .order_by(Organization.name.is_(None), Organization.name, Device.name))
    if device_ids is not None:
        stmt = stmt.where(Device.id.in_([str(i) for i in device_ids]))
    return list(db.scalars(stmt))


def run_bulk(db: Session, settings: Settings, action: str, devices: list[Device], actor: str,
             pickup_window: timedelta = DEFAULT_PICKUP_WINDOW) -> BulkResult:
    """Queue `action` on each firewall that needs it. Raises TaskError for an action that cannot run at all."""
    if action not in BULK_ACTIONS:
        raise TaskError("That task cannot be run in bulk")
    if action in CHANGE_ACTIONS and not settings.enable_firewall_changes:
        raise TaskError("Firewall changes are turned off on this server")
    downloads = settings.data_dir / "downloads"
    package = None
    if action == TaskType.update_agent.value:
        package = latest_package(downloads)
        if package is None:
            raise TaskError("No agent package is available on this server")
    result = BulkResult()
    for device in devices:
        try:
            if action == "check_now":
                check_now(db, device, actor)
            elif package is not None:
                if not agent_outdated(device.agent_version, package["version"]):
                    result.skip(UP_TO_DATE, device)
                    continue
                if has_open_task(db, device, TaskType.update_agent):
                    result.skip(BUSY, device)
                    continue
                update_agent(db, device, actor, package, downloads, pickup_window)
            elif action == "latest_branch":
                info = (device.inventory or {}).get("update_branch")
                target = latest_stable_branch(info)
                if target is None:
                    result.skip(NOT_REPORTED, device)  # agent before 0.2.10, or not checked in since
                    continue
                if isinstance(info, dict) and info.get("current") == target:
                    result.skip(UP_TO_DATE, device)
                    continue
                queue_task(db, device, TaskType.update_branch, {"branch": target}, actor=actor,
                           pickup_window=pickup_window, changes_enabled=True)
            elif action in (TaskType.upgrade_system.value, TaskType.upgrade_packages.value):
                ttype = TaskType(action)
                pending = _pending_update(device, action)
                if pending is None:
                    result.skip(NOT_REPORTED, device)
                    continue
                if not pending:
                    result.skip(UP_TO_DATE, device)
                    continue
                if has_open_task(db, device, TaskType.upgrade_system) or has_open_task(db, device, ttype):
                    result.skip(BUSY, device)
                    continue
                queue_task(db, device, ttype, actor=actor, pickup_window=pickup_window, changes_enabled=True)
            else:
                queue_task(db, device, TaskType(action), actor=actor, pickup_window=pickup_window)
            result.queued.append(device.name)
        except TaskError as exc:
            result.refused.append(f"{device.name}: {exc}")
    return result
