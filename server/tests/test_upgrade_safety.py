"""Upgrades: refused without free disk space; an alert when one stops making progress."""
from __future__ import annotations

from datetime import timedelta

import pytest
from conftest import ALL_CAPS, auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Alert, Device, DeviceStatus, Task, TaskStatus, TaskType, utcnow
from app.services import alerts as alert_svc
from app.services.tasks import TaskError, queue_task

GB = 1024**3


def _firewall(agent, db, free):
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS, system={"hostname": f"fw{free}", "unique_id": str(free)})
    agent.post("/api/agent/v1/checkin", json={"metrics": {"disk_pct": 90, "disk_free": free, "disk_total": 8 * GB}},
               headers=auth(creds["token"]))
    return creds, db.get(Device, creds["device_id"])


def test_upgrades_need_free_disk_space(client, db, agent):
    login(client)
    creds, device = _firewall(agent, db, int(0.4 * GB))
    with pytest.raises(TaskError, match="Not enough free disk space on the firewall: 410 MB free, 2.0 GB needed"):
        queue_task(db, device, TaskType.upgrade_system, actor="t", changes_enabled=True)
    assert not db.scalars(select(Task).where(Task.device_id == device.id)).all()  # not even the backup
    # The agent clears its package cache before giving up, so 1.5 GB free is let through (it decides).
    _, roomy = _firewall(agent, db, int(1.5 * GB))
    queue_task(db, roomy, TaskType.upgrade_system, actor="t", changes_enabled=True)
    # The page shows free space and offers to free some.
    page = client.get(f"/devices/{creds['device_id']}").text
    assert "MiB free" in page or "MB free" in page
    assert "Free disk space (package cache, old logs)" in page


@pytest.mark.changes
def test_stalled_upgrades_raise_an_alert_until_they_move_or_end(client, db, agent):
    creds, device = _firewall(agent, db, 5 * GB)
    queue_task(db, device, TaskType.upgrade_system, actor="t", changes_enabled=True)
    db.commit()
    wire = agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).json()["tasks"]
    up = next(t for t in wire if t["type"] == "upgrade_system")
    agent.post(f"/api/agent/v1/tasks/{up['id']}/result", headers=auth(creds["token"]), json={
        "status": "running", "output": "x", "result": {"progress": {"percent": 50, "step": "Installing the base system"}}})
    db.expire_all()
    task = db.get(Task, up["id"])
    assert task.result["progress_at"]

    alert_svc.check_stalled_upgrades(db, utcnow() + timedelta(minutes=10))
    assert not db.scalars(select(Alert).where(Alert.key.like("upgrade_stalled:%"))).all()
    alert_svc.check_stalled_upgrades(db, utcnow() + timedelta(minutes=25))
    db.commit()
    alert = db.scalar(select(Alert).where(Alert.key == f"upgrade_stalled:{task.id}"))
    assert alert.severity == "critical" and "no progress for 25 minutes (last step: Installing the base system)" in alert.message
    # A check-in does not clear it (it is not about the report)...
    agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"]))
    db.expire_all()
    assert db.get(Alert, alert.id).resolved_at is None
    # ...progress does, and so does the upgrade ending.
    alert_svc.check_stalled_upgrades(db, utcnow())
    db.commit()
    assert db.get(Alert, alert.id).resolved_at is not None
    alert_svc.check_stalled_upgrades(db, utcnow() + timedelta(minutes=25))
    db.commit()
    again = db.scalar(select(Alert).where(Alert.key == f"upgrade_stalled:{task.id}", Alert.resolved_at.is_(None)))
    assert again is not None
    task.status = TaskStatus.failed
    db.commit()
    alert_svc.check_stalled_upgrades(db, utcnow() + timedelta(minutes=30))
    db.commit()
    db.expire_all()
    assert db.get(Alert, again.id).resolved_at is not None
    # Offline mid-upgrade is a reboot, not a stall.
    device = db.get(Device, creds["device_id"])
    task.status, device.status = TaskStatus.running, DeviceStatus.offline
    db.commit()
    alert_svc.check_stalled_upgrades(db, utcnow() + timedelta(minutes=60))
    db.commit()
    assert not db.scalars(select(Alert).where(Alert.key.like("upgrade_stalled:%"), Alert.resolved_at.is_(None))).all()
