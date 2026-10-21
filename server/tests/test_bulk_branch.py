"""Run Task > Set update branch to latest stable, on the Firewalls page."""
from __future__ import annotations

import pytest
from conftest import ALL_CAPS, auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Task, TaskType
from app.services.tasks import latest_stable_branch

PLUS = {"current": "25_11_1", "branches": [
    {"name": "26_07", "descr": "Latest stable version (26.07)", "default": True},
    {"name": "25_11_1", "descr": "Previous stable version (25.11.1)", "default": False},
    {"name": "26_11_devel", "descr": "Development snapshots (26.11)", "default": False},
]}


def test_latest_stable_branch():
    assert latest_stable_branch(PLUS) == "26_07"
    # The newest by version even when pfSense's default is another one; snapshots never.
    assert latest_stable_branch({"branches": [{"name": "24_11", "descr": "Stable (24.11)", "default": True},
                                              {"name": "25_03", "descr": "Stable (25.03)"},
                                              {"name": "26_03_rc", "descr": "26.03 RC"}]}) == "25_03"
    # CE: names without versions; the default one.
    assert latest_stable_branch({"branches": [{"name": "Stable", "descr": "Latest stable version", "default": True},
                                              {"name": "Devel", "descr": "Latest development snapshots"}]}) == "Stable"
    assert latest_stable_branch(None) is None and latest_stable_branch({}) is None


@pytest.mark.changes
def test_bulk_switches_each_firewall_to_its_newest_stable_branch(client, db, agent):
    csrf = login(client)
    behind = enroll(agent, make_key(db), capabilities=ALL_CAPS, system={"hostname": "fw-behind", "unique_id": "a"})
    agent.post("/api/agent/v1/checkin", json={"update_branch": PLUS}, headers=auth(behind["token"]))
    on_it = enroll(agent, make_key(db), capabilities=ALL_CAPS, system={"hostname": "fw-current", "unique_id": "b"})
    agent.post("/api/agent/v1/checkin", json={"update_branch": {**PLUS, "current": "26_07"}}, headers=auth(on_it["token"]))
    silent = enroll(agent, make_key(db), capabilities=ALL_CAPS, system={"hostname": "fw-old", "unique_id": "c"})
    locked = enroll(agent, make_key(db), capabilities=["backup"], system={"hostname": "fw-locked", "unique_id": "d"})
    agent.post("/api/agent/v1/checkin", json={"update_branch": PLUS}, headers=auth(locked["token"]))

    assert "Set update branch to latest stable" in client.get("/devices").text
    r = client.post("/devices/bulk", data={"csrf_token": csrf, "task_type": "latest_branch", "device_ids": [
        behind["device_id"], on_it["device_id"], silent["device_id"], locked["device_id"]]})
    assert "switching 1 firewall(s); 1 already on it; 1 have not reported their branches; 1 refused" in r.text
    tasks = db.scalars(select(Task).where(Task.type == TaskType.update_branch)).all()
    assert [(t.device_id, t.payload) for t in tasks] == [(behind["device_id"], {"branch": "26_07"})]
