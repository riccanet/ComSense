"""Boot environments on the firewall's Configuration page: listed, and old ones removed (admins)."""
from __future__ import annotations

import pytest
from conftest import ALL_CAPS, auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Role, Task, TaskType, User
from app.security import hash_password

BES = [
    {"name": "default", "active": True, "next_boot": True, "mountpoint": "/", "space": "3.2G", "created": "2026-10-21 23:30"},
    {"name": "pre-upgrade-24.11", "active": False, "next_boot": False, "mountpoint": "-", "space": "1.1G",
     "created": "2026-10-21 23:09"},
]


def _firewall(agent, db):
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    agent.post("/api/agent/v1/checkin", json={"boot_environments": BES}, headers=auth(creds["token"]))
    return creds


@pytest.mark.changes
def test_boot_environments_are_listed_and_old_ones_removed(client, db, agent):
    csrf = login(client)
    creds = _firewall(agent, db)
    did = creds["device_id"]
    page = client.get(f"/devices/{did}/configuration").text
    assert "Boot environments" in page and "pre-upgrade-24.11" in page and "running now" in page and "next boot" in page
    assert page.count("/boot-environments/remove") == 1  # only the old one has a Remove button

    r = client.post(f"/devices/{did}/boot-environments/remove", data={"name": "default", "csrf_token": csrf})
    assert "cannot be removed" in r.text
    r = client.post(f"/devices/{did}/boot-environments/remove", data={"name": "nope", "csrf_token": csrf})
    assert "did not report" in r.text
    r = client.post(f"/devices/{did}/boot-environments/remove", data={"name": "pre-upgrade-24.11", "csrf_token": csrf})
    assert "Queued: remove boot environment pre-upgrade-24.11" in r.text and "removal queued" in r.text
    task = db.scalar(select(Task).where(Task.type == TaskType.be_destroy))
    assert task.payload == {"name": "pre-upgrade-24.11"}

    # The firewall's answer updates the list right away.
    wire = agent.post("/api/agent/v1/checkin", json={"boot_environments": BES}, headers=auth(creds["token"])).json()["tasks"]
    agent.post(f"/api/agent/v1/tasks/{wire[0]['id']}/result", headers=auth(creds["token"]), json={
        "status": "success", "output": "Removed", "result": {"boot_environments": BES[:1]}})
    assert "pre-upgrade-24.11" not in client.get(f"/devices/{did}/configuration").text


@pytest.mark.changes
def test_only_admins_remove_boot_environments(client, db, agent):
    creds = _firewall(agent, db)
    db.add(User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator))
    db.commit()
    csrf = login(client, "op", "operator-password-1")
    page = client.get(f"/devices/{creds['device_id']}/configuration").text
    assert "pre-upgrade-24.11" in page and "/boot-environments/remove" not in page
    r = client.post(f"/devices/{creds['device_id']}/boot-environments/remove",
                    data={"name": "pre-upgrade-24.11", "csrf_token": csrf})
    assert r.status_code == 403
