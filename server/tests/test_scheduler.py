from __future__ import annotations

import gzip
from dataclasses import replace
from datetime import timedelta

from conftest import auth, enroll, make_key
from sqlalchemy import func, select

from app.models import Backup, Device, Task, TaskStatus, TaskType, utcnow
from app.scheduler import run_once

CONFIG = b'<?xml version="1.0"?>\n<pfsense>\n<version>23.3</version>\n<n>{}</n>\n</pfsense>\n'


def _upload(client, token, n=0):
    body = gzip.compress(CONFIG.replace(b"{}", str(n).encode()))
    resp = client.post("/api/agent/v1/backups", content=body, headers=auth(token))
    assert resp.status_code == 200, resp.text
    return resp.json()


def _backup_tasks(db, device_id):
    return db.scalar(
        select(func.count()).select_from(Task).where(Task.device_id == device_id, Task.type == TaskType.backup)
    )


def test_unchanged_config_is_not_backed_up_every_minute(client, db, settings):
    creds = enroll(client, make_key(db))
    _upload(client, creds["token"])
    device = db.get(Device, creds["device_id"])

    # The only stored backup is two days old, but the firewall uploaded the same
    # config an hour ago (deduplicated). No new scheduled backup is due.
    db.execute(Backup.__table__.update().values(created_at=utcnow() - timedelta(days=2)))
    device.last_backup_at = utcnow() - timedelta(hours=1)
    db.commit()
    for _ in range(3):
        run_once(settings)
    assert _backup_tasks(db, device.id) == 0

    # Once the last upload is older than the schedule, exactly one task is queued...
    device.last_backup_at = utcnow() - timedelta(hours=25)
    db.commit()
    run_once(settings)
    run_once(settings)
    assert _backup_tasks(db, device.id) == 1

    # ...and after the agent completes it with an identical config, none follow.
    task = db.scalar(select(Task).where(Task.type == TaskType.backup))
    client.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"]))
    _upload(client, creds["token"])
    client.post(f"/api/agent/v1/tasks/{task.id}/result", json={"status": "success"}, headers=auth(creds["token"]))
    for _ in range(3):
        run_once(settings)
    db.expire_all()
    assert _backup_tasks(db, device.id) == 1
    assert db.scalar(select(func.count()).select_from(Backup)) == 1


def test_only_last_five_backups_are_kept_plus_pinned(client, db, settings):
    assert settings.backup_retention_count == 5
    creds = enroll(client, make_key(db))
    first = _upload(client, creds["token"], 0)
    pinned = db.get(Backup, first["backup_id"])
    pinned.pinned = True
    db.commit()
    for n in range(1, 9):
        _upload(client, creds["token"], n)
    db.expire_all()
    backups = db.scalars(select(Backup).order_by(Backup.id)).all()
    assert len(backups) == 6
    assert backups[0].id == first["backup_id"] and backups[0].pinned
    assert len([b for b in backups if not b.pinned]) == 5
    files = list((settings.backup_dir / creds["device_id"]).glob("*.enc"))
    assert len(files) == 6


def test_old_finished_tasks_are_purged(client, db, settings):
    creds = enroll(client, make_key(db))
    old = utcnow() - timedelta(days=settings.task_retention_days + 1)
    db.add_all(
        [
            Task(device_id=creds["device_id"], type=TaskType.check_updates, status=TaskStatus.success, created_at=old),
            Task(device_id=creds["device_id"], type=TaskType.check_updates, status=TaskStatus.pending, created_at=old),
            Task(device_id=creds["device_id"], type=TaskType.check_updates, status=TaskStatus.success),
        ]
    )
    db.commit()
    run_once(replace(settings, scheduled_backup_hours=0))
    statuses = sorted(t.status.value for t in db.scalars(select(Task)))
    assert statuses == ["pending", "success"]
