from __future__ import annotations

import gzip
import hashlib
from datetime import timedelta

from conftest import auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Alert, Backup, Device, DeviceStatus, Task, TaskStatus, TaskType, utcnow
from app.services.tasks import TaskError, queue_task

CONFIG_XML = b"""<?xml version="1.0"?>
<pfsense>
\t<version>23.3</version>
\t<revision><time>1700000000</time><description><![CDATA[admin@10.0.0.1: Saved rules]]></description></revision>
\t<system><hostname>fw1</hostname></system>
</pfsense>
"""


def test_enroll_requires_valid_key(client, db, agent):
    for body in ({}, {"enrollment_key": ""}, {"enrollment_key": "csfm_enr_wrong"}):
        resp = agent.post("/api/agent/v1/enroll", json=body)
        assert resp.status_code == 403
    assert db.scalar(select(Device)) is None


def test_revoked_expired_and_used_up_keys_are_rejected(client, db, agent):
    revoked = make_key(db, revoked=True)
    expired = make_key(db, expires_at=utcnow() - timedelta(minutes=1))
    single = make_key(db, max_uses=1)
    for key in (revoked, expired):
        assert agent.post("/api/agent/v1/enroll", json={"enrollment_key": key}).status_code == 403
    enroll(agent, single)
    resp = agent.post(
        "/api/agent/v1/enroll",
        json={"enrollment_key": single, "system": {"unique_id": "other"}},
    )
    assert resp.status_code == 403


def test_checkin_requires_token(client, db, agent):
    assert agent.post("/api/agent/v1/checkin", json={}).status_code == 401
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth("csfm_dev_nope")).status_code == 401


def test_enroll_and_checkin_records_inventory(client, db, agent):
    creds = enroll(agent, make_key(db))
    assert creds["token"].startswith("csfm_dev_")
    report = {
        "agent_version": "0.1.0",
        "capabilities": ["backup"],
        "system": {"hostname": "fw1", "edition": "plus", "version": "24.03-RELEASE"},
        "interfaces": [{"name": "wan", "descr": "WAN", "ipaddr": "198.51.100.7", "status": "up"}],
        "gateways": [{"name": "WAN_DHCP", "status": "down"}],
        "services": [{"name": "unbound", "running": True}],
        "metrics": {"cpu_pct": 12.5, "mem_pct": 40, "disk_pct": 95, "load": [0.2, 0.1, 0.1], "states": 120},
        "config": {"sha256": "f" * 64},
    }
    resp = agent.post("/api/agent/v1/checkin", json=report, headers=auth(creds["token"]))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "online"
    assert body["upload_backup"] is True

    device = db.get(Device, creds["device_id"])
    db.refresh(device)
    assert device.edition == "plus"
    assert device.wan_ip == "198.51.100.7"
    assert device.capabilities == ["backup"]
    keys = {a.key for a in db.scalars(select(Alert).where(Alert.resolved_at.is_(None)))}
    assert keys == {"gateway:WAN_DHCP", "disk"}

    report["gateways"][0]["status"] = "online"
    report["metrics"]["disk_pct"] = 50
    agent.post("/api/agent/v1/checkin", json=report, headers=auth(creds["token"]))
    db.expire_all()
    assert db.scalars(select(Alert).where(Alert.resolved_at.is_(None))).all() == []


def test_approval_gate(client, db, agent):
    creds = enroll(agent, make_key(db, require_approval=True))
    device = db.get(Device, creds["device_id"])
    assert device.status == DeviceStatus.pending
    try:
        queue_task(db, device, TaskType.backup)
        raise AssertionError("expected TaskError")
    except TaskError:
        pass
    resp = agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"]))
    assert resp.json() == {**resp.json(), "status": "pending", "tasks": []}
    gz = gzip.compress(CONFIG_XML)
    assert agent.post("/api/agent/v1/backups", content=gz, headers=auth(creds["token"])).status_code == 403


def test_disabled_device_is_rejected(client, db, agent):
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    device.status = DeviceStatus.disabled
    db.commit()
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).status_code == 403


def test_task_round_trip_and_capability_check(client, db, agent):
    creds = enroll(agent, make_key(db), capabilities=["backup"])
    device = db.get(Device, creds["device_id"])
    try:
        queue_task(db, device, TaskType.reboot, changes_enabled=True)
        raise AssertionError("reboot should need the reboot capability")
    except TaskError:
        pass
    task = queue_task(db, device, TaskType.check_updates)
    db.commit()

    tasks = agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).json()["tasks"]
    assert [t["type"] for t in tasks] == ["check_updates"]
    # Sent tasks are not handed out twice.
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).json()["tasks"] == []

    result = {"installed_version": "2.7.0", "version": "2.7.2", "update_available": True}
    resp = agent.post(
        f"/api/agent/v1/tasks/{task.id}/result",
        json={"status": "success", "result": result, "output": "ok"},
        headers=auth(creds["token"]),
    )
    assert resp.status_code == 200
    db.expire_all()
    assert db.get(Task, task.id).status == TaskStatus.success
    assert db.get(Device, device.id).updates["update_available"] is True


def test_task_results_are_scoped_to_device(client, db, agent):
    a = enroll(agent, make_key(db))
    b = enroll(agent, make_key(db), system={"unique_id": "other-box"})
    task = queue_task(db, db.get(Device, a["device_id"]), TaskType.check_updates)
    db.commit()
    resp = agent.post(
        f"/api/agent/v1/tasks/{task.id}/result", json={"status": "success"}, headers=auth(b["token"])
    )
    assert resp.status_code == 404


def test_backup_upload_dedup_and_encryption(client, db, settings, agent):
    creds = enroll(agent, make_key(db))
    digest = hashlib.sha256(CONFIG_XML).hexdigest()
    gz = gzip.compress(CONFIG_XML)
    headers = {**auth(creds["token"]), "X-CSFM-SHA256": digest, "X-CSFM-Reason": "config_change"}

    first = agent.post("/api/agent/v1/backups", content=gz, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["created"] is True
    second = agent.post("/api/agent/v1/backups", content=gz, headers=headers)
    assert second.json() == {**first.json(), "created": False}

    backup = db.scalar(select(Backup))
    assert backup.config_revision == "admin@10.0.0.1: Saved rules"
    stored = (settings.backup_dir / backup.path).read_bytes()
    assert stored.startswith(b"gAAAAA")  # Fernet token, not gzip or XML
    assert b"pfsense" not in stored

    bad = agent.post(
        "/api/agent/v1/backups", content=gz, headers={**headers, "X-CSFM-SHA256": "0" * 64}
    )
    assert bad.status_code == 400
    junk = agent.post("/api/agent/v1/backups", content=gzip.compress(b"hello"), headers=headers)
    assert junk.status_code == 400

    # Operators can download the decrypted file through the web UI.
    login(client)
    dl = client.get(f"/backups/{backup.id}/download")
    assert dl.status_code == 200
    assert dl.content == CONFIG_XML


def test_restore_download_requires_open_restore_task(client, db, agent):
    creds = enroll(agent, make_key(db))
    gz = gzip.compress(CONFIG_XML)
    backup_id = agent.post("/api/agent/v1/backups", content=gz, headers=auth(creds["token"])).json()["backup_id"]
    url = f"/api/agent/v1/backups/{backup_id}"
    assert agent.get(url, headers=auth(creds["token"])).status_code == 403

    queue_task(
        db, db.get(Device, creds["device_id"]), TaskType.restore_backup, {"backup_id": backup_id}, changes_enabled=True
    )
    db.commit()
    agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"]))
    resp = agent.get(url, headers=auth(creds["token"]))
    assert resp.status_code == 200
    assert gzip.decompress(resp.content) == CONFIG_XML


def test_reenroll_same_hardware_reuses_device_and_rotates_token(client, db, agent):
    key = make_key(db)
    first = enroll(agent, key)
    second = enroll(agent, key)
    assert first["device_id"] == second["device_id"]
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth(first["token"])).status_code == 401
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth(second["token"])).status_code == 200


def test_token_rotation(client, db, agent):
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    device.token_rotated_at = utcnow() - timedelta(days=31)
    db.commit()
    body = agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).json()
    assert body["rotate_token"] is True
    new = agent.post("/api/agent/v1/token/rotate", headers=auth(creds["token"])).json()["token"]
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).status_code == 401
    assert "rotate_token" not in agent.post("/api/agent/v1/checkin", json={}, headers=auth(new)).json()
