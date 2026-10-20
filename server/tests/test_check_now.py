from __future__ import annotations

import hashlib
import re
import time

from conftest import auth, csrf_from, enroll, login, make_key
from sqlalchemy import select

from app.api import agent as agent_api
from app.models import Task, TaskStatus, TaskType
from app.services import agentpkg
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
    # This firewall reports 0.1.0, which cannot replace itself: it is sent the bootstrap package.
    expected = agentpkg.package_for(settings.data_dir / "downloads", package, "0.1.0")
    assert task.payload == {"version": package["version"], "file": package["name"], "sha256": expected["sha256"]}

    # The agent downloads it over its own authenticated API.
    data = agent.get(f"/api/agent/v1/agent-package/{package['name']}", headers=auth(creds["token"]))
    assert data.status_code == 200 and hashlib.sha256(data.content).hexdigest() == expected["sha256"]
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


def test_device_page_follows_the_firewall(client, db, agent):
    creds = enroll(agent, make_key(db))
    csrf = login(client)
    did = creds["device_id"]
    page = client.get(f"/devices/{did}").text
    token = re.search(r'data-poll-token="([0-9a-f]+)"', page).group(1)
    assert client.get(f"/devices/{did}/poll").json() == {"token": token}
    # A plain check-in does not change it (the page is not reloaded every minute)...
    agent.post("/api/agent/v1/checkin", json={"system": {"hostname": "fw"}}, headers=auth(creds["token"]))
    assert client.get(f"/devices/{did}/poll").json()["token"] == token
    # ...a task moving on does, and so does a new agent version.
    client.post(f"/devices/{did}/check-now", data={"csrf_token": csrf})
    queued = client.get(f"/devices/{did}/poll").json()["token"]
    assert queued != token
    agent.post("/api/agent/v1/checkin", json={"system": {"hostname": "fw"}}, headers=auth(creds["token"]))
    assert client.get(f"/devices/{did}/poll").json()["token"] != queued


def test_failed_in_place_update_explains_the_one_time_manual_install(client, db, agent, settings):
    creds = enroll(agent, make_key(db))
    csrf = login(client)
    client.post(f"/devices/{creds['device_id']}/update-agent", data={"csrf_token": csrf})
    (task,) = _tasks(db, creds["device_id"], TaskType.update_agent)
    agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"]))  # picks the task up
    agent.post(f"/api/agent/v1/tasks/{task.id}/result", headers=auth(creds["token"]), json={
        "status": "failed", "output": "The agent is still at 0.2.7 after installing 0.2.10.\nInstalling "
        "pfSense-pkg-ComSense-0.2.10...\nthe most recent version of pfSense-pkg-ComSense-0.2.7 is already installed"})
    db.expire_all()
    task = db.get(Task, task.id)
    assert task.status.value == "failed" and "pkg-static add -f" in task.output


def test_firewalls_list_shows_the_agent_version(client, db, agent, settings):
    package = agentpkg.latest_package(settings.data_dir / "downloads")
    old = enroll(agent, make_key(db), system={"hostname": "old-fw", "unique_id": "o1"})
    new = enroll(agent, make_key(db), system={"hostname": "new-fw", "unique_id": "n1"})
    agent.post("/api/agent/v1/checkin", json={"agent_version": "0.2.7"}, headers=auth(old["token"]))
    agent.post("/api/agent/v1/checkin", json={"agent_version": package["version"]}, headers=auth(new["token"]))
    login(client)
    page = client.get("/devices").text
    assert "<th>Agent</th>" in page
    old_row = page[page.index("old-fw"):page.index("</tr>", page.index("old-fw"))]
    new_row = page[page.index("new-fw"):page.index("</tr>", page.index("new-fw"))]
    assert "0.2.7" in old_row and ">update<" in old_row
    assert package["version"] in new_row and ">update<" not in new_row


def test_firewalls_list_is_by_customer_with_run_task_at_the_top(client, db, agent):
    from app.models import Organization
    zeta, acme = Organization(name="Zeta Corp"), Organization(name="acme")
    db.add_all([zeta, acme])
    db.commit()
    for host, org in (("a-fw", zeta), ("b-fw", acme), ("c-fw", None), ("d-fw", acme)):
        enroll(agent, make_key(db, organization_id=org.id if org else None), system={"hostname": host, "unique_id": host})
    login(client)
    page = client.get("/devices").text
    order = [h for h in ("b-fw", "d-fw", "a-fw", "c-fw")]
    assert sorted(order, key=page.index) == order  # acme, Zeta Corp, then no customer
    assert page.index("Run Task:") < page.index("<table")
    assert "With selected" not in page and "/devices/assign" not in page
