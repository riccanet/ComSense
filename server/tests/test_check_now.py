from __future__ import annotations

import hashlib
import time

from conftest import auth, csrf_from, enroll, login, make_key
from sqlalchemy import select

from app.api import agent as agent_api
from app.models import Task, TaskStatus, TaskType
from app.services.agentpkg import agent_outdated, latest_package


def _tasks(db, device_id, ttype):
    db.expire_all()
    return db.scalars(select(Task).where(Task.device_id == device_id, Task.type == ttype)).all()


def test_wait_answers_when_work_is_queued(client, db, agent, monkeypatch):
    monkeypatch.setattr(agent_api, "WAIT_POLL", 0.05)
    creds = enroll(agent, make_key(db))
    start = time.monotonic()
    assert agent.get("/api/agent/v1/wait?timeout=1", headers=auth(creds["token"])).json() == {"wake": False}
    assert time.monotonic() - start >= 0.9
    assert agent.get("/api/agent/v1/wait?timeout=1").status_code == 401

    csrf = login(client)
    client.post(f"/devices/{creds['device_id']}/check-now", data={"csrf_token": csrf})
    client.post(f"/devices/{creds['device_id']}/check-now", data={"csrf_token": csrf})
    assert len(_tasks(db, creds["device_id"], TaskType.refresh_inventory)) == 1  # not queued twice
    start = time.monotonic()
    assert agent.get("/api/agent/v1/wait?timeout=30", headers=auth(creds["token"])).json() == {"wake": True}
    assert time.monotonic() - start < 5

    # The next check-in carries the task.
    resp = agent.post("/api/agent/v1/checkin", json={"system": {"hostname": "fw"}}, headers=auth(creds["token"]))
    assert [t["type"] for t in resp.json()["tasks"]] == ["refresh_inventory"]


def test_agent_version_comparison():
    assert agent_outdated("0.1.8", "0.1.9")
    assert agent_outdated("0.1.9", "0.1.10")
    assert not agent_outdated("0.1.9", "0.1.9")
    assert not agent_outdated("0.2.0", "0.1.9")
    assert not agent_outdated("", "0.1.9")


def test_update_agent_button_queues_the_current_package(client, db, agent, settings):
    creds = enroll(agent, make_key(db))  # reports agent 0.1.0
    csrf = login(client)
    package = latest_package(settings.data_dir / "downloads")
    assert package and package["version"] != "0.1.0"
    page = client.get(f"/devices/{creds['device_id']}").text
    assert "Check now" in page and f"Update agent to {package['version']}" in page

    client.post(f"/devices/{creds['device_id']}/update-agent", data={"csrf_token": csrf})
    (task,) = _tasks(db, creds["device_id"], TaskType.update_agent)
    assert task.payload == {"version": package["version"], "file": package["name"], "sha256": package["sha256"]}

    # The agent downloads it over its own authenticated API.
    data = agent.get(f"/api/agent/v1/agent-package/{package['name']}", headers=auth(creds["token"]))
    assert data.status_code == 200 and hashlib.sha256(data.content).hexdigest() == package["sha256"]
    assert agent.get(f"/api/agent/v1/agent-package/{package['name']}").status_code == 401
    for bad in ("..%2Fsecret.key", "other.pkg", "pfSense-pkg-ComSense-9.9.9.pkg"):
        assert agent.get(f"/api/agent/v1/agent-package/{bad}", headers=auth(creds["token"])).status_code == 404

    # Once the agent reports the new version there is nothing to update.
    agent.post("/api/agent/v1/checkin", json={"agent_version": package["version"], "system": {"hostname": "fw"}},
               headers=auth(creds["token"]))
    page = client.get(f"/devices/{creds['device_id']}").text
    assert "Update agent to" not in page
    page = client.post(f"/devices/{creds['device_id']}/update-agent", data={"csrf_token": csrf}).text
    assert "already current" in page


def test_bulk_check_now_and_update(client, db, agent):
    a = enroll(agent, make_key(db))
    b = enroll(agent, make_key(db), system={"hostname": "fw2", "unique_id": "zzz"})
    agent.post("/api/agent/v1/checkin", json={"agent_version": "99.0.0", "system": {"hostname": "fw2"}},
               headers=auth(b["token"]))
    csrf = login(client)
    page = client.get("/devices").text
    assert 'value="check_now"' in page and 'value="update_agent"' in page
    ids = [a["device_id"], b["device_id"]]
    page = client.post("/devices/bulk", data={"device_ids": ids, "task_type": "check_now", "csrf_token": csrf}).text
    assert "queued on 2 firewall(s)" in page
    page = client.post("/devices/bulk", data={"device_ids": ids, "task_type": "update_agent",
                                                   "csrf_token": csrf_from(page)}).text
    assert "queued on 1 firewall(s); skipped 1" in page
    assert len(_tasks(db, a["device_id"], TaskType.update_agent)) == 1
    assert all(t.status == TaskStatus.pending for t in _tasks(db, b["device_id"], TaskType.refresh_inventory))
