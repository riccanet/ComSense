"""Logs on the firewall's page: fetched on demand, searched on the firewall, shown parsed."""
from __future__ import annotations

from conftest import ALL_CAPS, auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Task, TaskType, User, Role

SYSTEM = [
    "<134>1 2026-10-21T03:05:09.1+00:00 fw php-fpm 451 - - /index.php: Successful login for user 'admin' from: 192.168.1.5",
    "Oct 21 03:06:10 fw sshd[1234]: Accepted publickey for root from 192.168.1.9",
]
FIREWALL = [
    "<134>1 2026-10-21T03:05:09.1+00:00 fw filterlog 123 - - 5,,,1000000103,mvneta0.4090,match,block,in,4,0x0,,64,1234,0,DF,"
    "6,tcp,60,203.0.113.5,71.162.238.18,51234,22,0,S,123,,64240,,mss",
]


def _fetch(client, agent, creds, csrf, **form):
    r = client.post(f"/devices/{creds['device_id']}/logs", data={"csrf_token": csrf, **form})
    assert r.status_code == 200
    tasks = agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).json()["tasks"]
    return r, next(t for t in tasks if t["type"] == "read_logs")


def test_logs_are_fetched_searched_and_shown(client, db, agent):
    csrf = login(client)
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    did = creds["device_id"]
    agent.post("/api/agent/v1/checkin", json={"interfaces": [{"name": "wan", "descr": "WAN", "if": "mvneta0.4090"}]},
               headers=auth(creds["token"]))
    assert 'href="/devices/' + did + '/logs"' in client.get(f"/devices/{did}").text

    r, wire = _fetch(client, agent, creds, csrf, log="system", lines="250", search=" admin ")
    assert wire["payload"] == {"log": "system", "lines": 250, "search": "admin"}
    assert "Fetching the System log" in r.text
    agent.post(f"/api/agent/v1/tasks/{wire['id']}/result", headers=auth(creds["token"]), json={
        "status": "success", "output": "system.log: 2 line(s)",
        "result": {"log": "system", "lines": SYSTEM, "matched": 2, "scanned": 500, "search": "admin"}})
    page = client.get(f"/devices/{did}/logs").text  # the last fetch stays on the page
    assert "php-fpm" in page and "Successful login for user" in page and "2026-10-21 03:05:09" in page
    assert page.index("Accepted publickey") < page.index("Successful login")  # newest first
    assert 'value="admin"' in page and "data-filter-rows" in page

    _, wire = _fetch(client, agent, creds, csrf, log="firewall", lines="100", search="")
    agent.post(f"/api/agent/v1/tasks/{wire['id']}/result", headers=auth(creds["token"]), json={
        "status": "success", "output": "filter.log: 1 line(s)", "result": {"log": "firewall", "lines": FIREWALL}})
    page = client.get(f"/devices/{did}/logs?task={wire['id']}").text
    assert "rule-block" in page and "203.0.113.5:51234" in page and "71.162.238.18:22" in page
    assert "<td>WAN</td>" in page  # the interface's name, not its device

    assert client.post(f"/devices/{did}/logs", data={"csrf_token": csrf, "log": "../etc", "lines": "100"}).status_code == 400
    assert not db.scalars(select(Task).where(Task.type == TaskType.read_logs, Task.status == "pending")).all()


def test_viewers_cannot_read_logs(client, db, agent):
    from conftest import ADMIN_PASSWORD  # noqa: F401
    from app.security import hash_password

    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    db.add(User(username="viewer1", password_hash=hash_password("viewer-password-123"), role=Role.viewer))
    db.commit()
    login(client, "viewer1", "viewer-password-123")
    assert client.get(f"/devices/{creds['device_id']}/logs").status_code == 403
