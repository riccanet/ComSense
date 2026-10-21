"""Upgrades are preceded by a pinned backup of the configuration."""
from __future__ import annotations

import gzip

from conftest import ALL_CAPS, auth, enroll, make_key
from sqlalchemy import select

from app.models import Backup, Device, Task, TaskType
from app.services.tasks import queue_task

CONFIG = b"<?xml version='1.0'?><pfsense><version>23.3</version><revision><time>1</time></revision></pfsense>"


def _upload(agent, token, xml, reason):
    return agent.post("/api/agent/v1/backups", content=gzip.compress(xml),
                      headers={**auth(token), "X-CSFM-Reason": reason}).json()


def test_upgrades_queue_a_backup_first(client, db, agent):
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    device = db.get(Device, creds["device_id"])
    queue_task(db, device, TaskType.upgrade_system, actor="t", changes_enabled=True)
    queue_task(db, device, TaskType.upgrade_packages, actor="t", changes_enabled=True)  # one backup is enough
    db.commit()
    tasks = db.scalars(select(Task).where(Task.device_id == device.id).order_by(Task.id)).all()
    assert [t.type for t in tasks] == [TaskType.backup, TaskType.upgrade_system, TaskType.upgrade_packages]
    assert tasks[0].payload == {"reason": "pre_upgrade"}

    # Without the backup permission the upgrade is queued alone.
    other = enroll(agent, make_key(db), capabilities=["upgrade"], system={"hostname": "fw2", "unique_id": "u2"})
    queue_task(db, db.get(Device, other["device_id"]), TaskType.upgrade_system, actor="t", changes_enabled=True)
    db.commit()
    assert [t.type for t in db.scalars(select(Task).where(Task.device_id == other["device_id"]))] == [TaskType.upgrade_system]


def test_pre_upgrade_backups_are_pinned(client, db, agent):
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    new = _upload(agent, creds["token"], CONFIG, "pre_upgrade")
    assert db.get(Backup, new["backup_id"]).pinned
    # An unchanged configuration is the existing backup: it becomes the pre-upgrade one, pinned.
    other = CONFIG.replace(b"23.3", b"23.4")
    plain = _upload(agent, creds["token"], other, "scheduled")
    db.expire_all()
    assert not db.get(Backup, plain["backup_id"]).pinned
    again = _upload(agent, creds["token"], other, "pre_upgrade")
    db.expire_all()
    backup = db.get(Backup, again["backup_id"])
    assert again["backup_id"] == plain["backup_id"] and backup.pinned and backup.reason == "pre_upgrade"
