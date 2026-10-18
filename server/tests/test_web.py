from __future__ import annotations

import json
import re

from conftest import ADMIN_PASSWORD, csrf_from, enroll, login, make_key
from sqlalchemy import select

from app.models import Device, EnrollmentKey, Policy, Role, Task, User
from app.security import hash_password


def test_pages_require_login(client):
    for path in ("/", "/devices", "/policies", "/keys", "/users", "/audit"):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 303 and resp.headers["location"] == "/login", path


def test_bad_password(client):
    token = csrf_from(client.get("/login").text)
    resp = client.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": token})
    assert resp.status_code == 401


def test_post_without_csrf_is_rejected(client):
    login(client)
    resp = client.post("/organizations", data={"name": "Acme"})
    assert resp.status_code == 403


def test_all_pages_render(client, db):
    csrf = login(client)
    creds = enroll(client, make_key(db))
    # A sparse report, as an agent on an unusual box might send, must still render.
    client.post(
        "/api/agent/v1/checkin",
        json={
            "interfaces": [{"name": "lan"}, {"name": "wan", "inbytes": 5, "status": "up"}],
            "gateways": [{"name": "GW"}],
            "services": [{"name": "x"}],
            "metrics": {"load": [0.1]},
            "updates": {"update_available": True},
        },
        headers={"Authorization": f"Bearer {creds['token']}"},
    )
    resp = client.post(
        "/policies",
        data={"name": "p1", "type": "system", "content": json.dumps({"timezone": "UTC"}), "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    policy_id = db.scalar(select(Policy.id))
    for path in (
        "/",
        "/devices",
        f"/devices/{creds['device_id']}",
        "/policies",
        "/policies/new",
        f"/policies/{policy_id}",
        "/alerts",
        "/organizations",
        "/keys",
        "/users",
        "/audit",
        "/account",
    ):
        resp = client.get(path)
        assert resp.status_code == 200, (path, resp.text[:500])


def test_create_enrollment_key_shows_once_and_stores_hash(client, db):
    csrf = login(client)
    resp = client.post(
        "/keys",
        data={"name": "rollout", "expires_days": "7", "max_uses": "", "require_approval": "true", "csrf_token": csrf},
    )
    assert resp.status_code == 200
    key = re.search(r'value="(pfm_enr_[^"]+)"', resp.text).group(1)
    assert key not in client.get("/keys").text
    stored = db.scalar(select(EnrollmentKey))
    assert stored.key_hash != key and key not in stored.key_hash
    assert enroll(client, key)["status"] == "pending"  # checkbox is ticked by default in the form


def test_viewer_cannot_operate(client, db):
    db.add(User(username="viewer", password_hash=hash_password(ADMIN_PASSWORD), role=Role.viewer))
    db.commit()
    creds = enroll(client, make_key(db))
    csrf = login(client, "viewer")
    resp = client.post(
        f"/devices/{creds['device_id']}/tasks", data={"task_type": "reboot", "csrf_token": csrf}
    )
    assert resp.status_code == 403
    assert db.scalar(select(Task)) is None


def test_operator_queues_task_and_admin_approves(client, db):
    csrf = login(client)
    creds = enroll(client, make_key(db, require_approval=True))
    device_url = f"/devices/{creds['device_id']}"
    client.post(f"{device_url}/status", data={"action": "approve", "csrf_token": csrf})
    db.expire_all()
    assert db.get(Device, creds["device_id"]).status.value == "offline"
    resp = client.post(f"{device_url}/tasks", data={"task_type": "backup", "csrf_token": csrf})
    assert resp.status_code == 200
    assert db.scalar(select(Task)).type.value == "backup"


def test_invalid_policy_shows_error(client):
    csrf = login(client)
    resp = client.post(
        "/policies",
        data={"name": "bad", "type": "system", "content": "{not json", "csrf_token": csrf},
    )
    assert resp.status_code == 400
    assert "not valid JSON" in resp.text


def test_security_headers(client):
    resp = client.get("/login")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"
