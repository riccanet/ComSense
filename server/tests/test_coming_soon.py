"""Firewall-changing features are "coming soon" unless CSFM_ENABLE_FIREWALL_CHANGES is set."""
from __future__ import annotations

import gzip
import json

import pytest
from conftest import auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Backup, Device, Policy, PolicyAssignment, PolicyType, Task, TaskType
from app.services.policies import reconcile_device_policies
from app.services.tasks import SAFE_TASKS, TaskError, queue_task

CHANGE_TASKS = [t for t in TaskType if t not in SAFE_TASKS]
CONFIG_XML = b'<?xml version="1.0"?>\n<pfsense>\n<version>23.3</version>\n</pfsense>\n'


def test_changes_are_off_by_default(settings):
    assert settings.enable_firewall_changes is False


@pytest.mark.parametrize("ttype", CHANGE_TASKS)
def test_change_tasks_are_refused(client, db, agent, ttype):
    device = db.get(Device, enroll(agent, make_key(db))["device_id"])
    with pytest.raises(TaskError, match="Coming soon"):
        queue_task(db, device, ttype)


@pytest.mark.parametrize("ttype", sorted(SAFE_TASKS, key=lambda t: t.value))
def test_safe_tasks_still_work(client, db, agent, ttype):
    device = db.get(Device, enroll(agent, make_key(db))["device_id"])
    queue_task(db, device, ttype)


def test_web_refuses_change_actions(client, db, agent):
    csrf = login(client)
    creds = enroll(agent, make_key(db))
    device_url = f"/devices/{creds['device_id']}"
    resp = client.post(f"{device_url}/tasks", data={"task_type": "reboot", "csrf_token": csrf})
    assert "Coming soon" in resp.text
    resp = client.post(f"{device_url}/tasks", data={"task_type": "restart_service", "service": "x", "csrf_token": csrf})
    assert "Coming soon" in resp.text
    resp = client.post(
        "/policies",
        data={"name": "p", "type": "system", "content": json.dumps({"timezone": "UTC"}), "csrf_token": csrf},
    )
    assert resp.status_code == 403 and "Coming soon" in resp.text
    backup_id = agent.post(
        "/api/agent/v1/backups", content=gzip.compress(CONFIG_XML), headers=auth(creds["token"])
    ).json()["backup_id"]
    resp = client.post(f"/backups/{backup_id}/restore", data={"confirm": "x", "csrf_token": csrf})
    assert resp.status_code == 403
    assert db.scalar(select(Task).where(Task.type != TaskType.backup)) is None
    # Safe actions are unaffected.
    client.post(f"{device_url}/tasks", data={"task_type": "check_updates", "csrf_token": csrf})
    assert db.scalar(select(Task).where(Task.type == TaskType.check_updates)) is not None
    assert db.get(Backup, backup_id) is not None


def test_existing_policies_are_not_pushed(client, db, agent):
    creds = enroll(agent, make_key(db))
    policy = Policy(name="sys", type=PolicyType.system, content={"timezone": "UTC"})
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, all_devices=True))
    db.commit()
    tasks = agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).json()["tasks"]
    assert tasks == []
    assert reconcile_device_policies(db, db.get(Device, creds["device_id"])) == []


def test_pages_show_coming_soon(client, db, agent):
    login(client)
    creds = enroll(agent, make_key(db))
    agent.post(
        "/api/agent/v1/checkin",
        json={"services": [{"name": "unbound", "running": True}], "packages": [{"name": "pfSense-pkg-x", "version": "1"}]},
        headers=auth(creds["token"]),
    )
    page = client.get(f"/devices/{creds['device_id']}").text
    assert "Coming soon" in page
    assert "Reboot (coming soon)" in page and "Upgrade pfSense (reboots) (coming soon)" in page
    assert 'value="install_package"' not in page
    assert 'name="policy_id"' not in page
    policies = client.get("/policies").text
    assert "Coming soon" in policies and "/policies/new" not in policies
    assert client.get("/policies/new", follow_redirects=False).headers["location"] == "/policies"
    nav = client.get("/").text
    assert 'class="nav-soon"' in nav


@pytest.mark.changes
def test_enabling_changes_unlocks_them(client, db, agent):
    login(client)
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    queue_task(db, device, TaskType.reboot, changes_enabled=True)
    page = client.get(f"/devices/{creds['device_id']}").text
    assert "(coming soon)" not in page and "nav-soon" not in page
