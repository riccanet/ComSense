"""Periodic housekeeping: offline detection, task timeouts, scheduled backups, retention."""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from sqlalchemy import delete, select

from .config import Settings
from .db import session_factory
from .models import Backup, Device, DeviceStatus, Metric, TaskType, aware, utcnow
from .services import alerts as alert_svc
from .services.tasks import TaskError, expire_stale_tasks, has_open_task, queue_task

log = logging.getLogger("comsense.scheduler")


def run_once(settings: Settings) -> None:
    now = utcnow()
    with session_factory()() as db:
        cutoff = now - timedelta(seconds=settings.offline_after)
        for device in db.scalars(select(Device).where(Device.status == DeviceStatus.online)):
            if device.last_seen_at is None or aware(device.last_seen_at) < cutoff:
                device.status = DeviceStatus.offline
                alert_svc.raise_offline(db, device)

        expire_stale_tasks(db, now)

        if settings.scheduled_backup_hours > 0:
            due = now - timedelta(hours=settings.scheduled_backup_hours)
            for device in db.scalars(select(Device).where(Device.status == DeviceStatus.online)):
                if "backup" not in (device.capabilities or []):
                    continue
                latest = db.scalar(
                    select(Backup.created_at)
                    .where(Backup.device_id == device.id)
                    .order_by(Backup.created_at.desc())
                    .limit(1)
                )
                if latest is not None and aware(latest) > due:
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
        db.commit()


async def scheduler_loop(settings: Settings, interval: float = 60.0) -> None:
    while True:
        try:
            await asyncio.to_thread(run_once, settings)
        except Exception:  # keep the loop alive; the next pass retries
            log.exception("Scheduler pass failed")
        await asyncio.sleep(interval)
