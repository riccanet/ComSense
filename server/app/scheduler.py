"""Periodic housekeeping: offline detection, task timeouts, scheduled jobs and backups, retention."""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import delete, select

from .config import Settings
from .db import session_factory
from .models import Device, DeviceStatus, Metric, Task, TaskStatus, TaskType, aware, utcnow
from .services import alerts as alert_svc
from .services.notifications import send_alert_notifications
from .services.schedules import run_due_jobs
from .services.tasks import TaskError, expire_stale_tasks, has_open_task, queue_task

log = logging.getLogger("comsense.scheduler")

FINISHED_STATES = (TaskStatus.success, TaskStatus.failed, TaskStatus.cancelled, TaskStatus.expired)


def run_once(settings: Settings) -> None:
    now = utcnow()
    with session_factory()() as db:
        cutoff = now - timedelta(seconds=settings.offline_after)
        for device in db.scalars(select(Device).where(Device.status == DeviceStatus.online)):
            if device.last_seen_at is None or aware(device.last_seen_at) < cutoff:
                device.status = DeviceStatus.offline
                alert_svc.raise_offline(db, device)

        expire_stale_tasks(db, now)
        run_due_jobs(db, settings, now)
        alert_svc.check_stalled_upgrades(db, now)
        db.flush()
        try:
            send_alert_notifications(db, settings)
        except Exception:  # email trouble must never stop housekeeping
            log.exception("Sending alert emails failed")

        if settings.scheduled_backup_hours > 0:
            due = now - timedelta(hours=settings.scheduled_backup_hours)
            for device in db.scalars(select(Device).where(Device.status == DeviceStatus.online)):
                if "backup" not in (device.capabilities or []):
                    continue
                # An unchanged config is deduplicated, so the newest Backup row can be
                # old; last_backup_at records that the firewall did upload recently.
                if device.last_backup_at is not None and aware(device.last_backup_at) > due:
                    continue
                if has_open_task(db, device, TaskType.backup):
                    continue
                try:
                    queue_task(db, device, TaskType.backup, {"reason": "scheduled"}, actor="scheduler")
                except TaskError:
                    pass

        db.execute(
            delete(Metric).where(Metric.ts < now - timedelta(days=settings.metrics_retention_days))
        )
        if settings.task_retention_days > 0:
            db.execute(
                delete(Task).where(
                    Task.status.in_(FINISHED_STATES),
                    Task.created_at < now - timedelta(days=settings.task_retention_days),
                )
            )
        db.commit()


async def scheduler_loop(settings: Settings, interval: float = 60.0) -> None:
    while True:
        try:
            await asyncio.to_thread(run_once, settings)
        except Exception:  # keep the loop alive; the next pass retries
            log.exception("Scheduler pass failed")
        await asyncio.sleep(interval)
