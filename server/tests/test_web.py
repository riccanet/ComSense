from __future__ import annotations

import json
import re

import pytest

from conftest import ADMIN_PASSWORD, csrf_from, enroll, login, make_key
from sqlalchemy import select

from app.enrollment import parse_code
from app.models import Device, EnrollmentKey, Policy, Role, Task, User
from app.security import hash_password
from app.tls import ensure_agent_tls


def test_pages_require_login(client):
    for path in ("/", "/devices", "/configurations/aliases", "/keys", "/users", "/audit"):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 303 and resp.headers["location"] == "/login", path


def test_bad_password(client):
    token = csrf_from(client.get("/login").text)
    resp = client.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": token})
    assert resp.status_code == 401


def test_post_without_csrf_is_rejected(client):
    login(client)
    resp = client.post("/customers", data={"name": "Acme"})
    assert resp.status_code == 403


@pytest.mark.changes
def test_all_pages_render(client, db, agent):
    csrf = login(client)
    creds = enroll(agent, make_key(db))
    # A sparse report, as an agent on an unusual box might send, must still render.
    agent.post(
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
        "/configurations",
        data={"name": "p1", "type": "system", "content": json.dumps({"timezone": "UTC"}), "csrf_token": csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    policy_id = db.scalar(select(Policy.id))
    for path in (
        "/",
        "/devices",
        f"/devices/{creds['device_id']}",
        "/configurations/aliases",
        "/configurations/rules",
        "/configurations/nat",
        "/configurations/groups",
        "/configurations/advanced",
        "/configurations/new?type=port_forward",
        f"/configurations/{policy_id}",
        "/alerts",
        "/customers",
        "/keys",
        "/users",
        "/audit",
        "/account",
    ):
        resp = client.get(path)
        assert resp.status_code == 200, (path, resp.text[:500])


def test_create_enrollment_key_shows_once_and_stores_hash(client, db, agent, settings):
    csrf = login(client)
    resp = client.post(
        "/keys",
        data={"name": "rollout", "expires_days": "7", "max_uses": "", "require_approval": "true", "csrf_token": csrf},
    )
    assert resp.status_code == 200
    code = re.search(r'value="(csfm1\.[^"]+)"', resp.text).group(1)
    parsed = parse_code(code)
    key = parsed["key"]
    assert key.startswith("csfm_enr_")
    assert parsed["url"] == "https://comsense.test:10443"
    assert parsed["pin"] == ensure_agent_tls(settings).pin  # self-issued certificate is pinned
    assert key not in client.get("/keys").text
    stored = db.scalar(select(EnrollmentKey))
    assert stored.key_hash != key and key not in stored.key_hash
    assert enroll(agent, key)["status"] == "pending"  # checkbox is ticked by default in the form


def test_viewer_cannot_operate(client, db, agent):
    db.add(User(username="viewer", password_hash=hash_password(ADMIN_PASSWORD), role=Role.viewer))
    db.commit()
    creds = enroll(agent, make_key(db))
    csrf = login(client, "viewer")
    resp = client.post(
        f"/devices/{creds['device_id']}/tasks", data={"task_type": "reboot", "csrf_token": csrf}
    )
    assert resp.status_code == 403
    assert db.scalar(select(Task)) is None


def test_operator_queues_task_and_admin_approves(client, db, agent):
    csrf = login(client)
    creds = enroll(agent, make_key(db, require_approval=True))
    device_url = f"/devices/{creds['device_id']}"
    client.post(f"{device_url}/status", data={"action": "approve", "csrf_token": csrf})
    db.expire_all()
    assert db.get(Device, creds["device_id"]).status.value == "offline"
    resp = client.post(f"{device_url}/tasks", data={"task_type": "backup", "csrf_token": csrf})
    assert resp.status_code == 200
    assert db.scalar(select(Task)).type.value == "backup"


@pytest.mark.changes
def test_invalid_policy_shows_error(client):
    csrf = login(client)
    resp = client.post(
        "/configurations",
        data={"name": "bad", "type": "system", "content": "{not json", "csrf_token": csrf},
    )
    assert resp.status_code == 400
    assert "not valid JSON" in resp.text


def test_security_headers(client):
    resp = client.get("/login")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["x-frame-options"] == "DENY"


def test_theme_cookie_is_rendered_server_side(client):
    assert 'data-theme="auto"' in client.get("/login").text
    for theme in ("light", "dark", "auto"):
        client.cookies.set("csfm_theme", theme)
        html = client.get("/login").text
        assert f'data-theme="{theme}"' in html
        assert f'data-theme-set="{theme}" aria-pressed="true"' in html
    client.cookies.set("csfm_theme", '"><script>x</script>')
    assert 'data-theme="auto"' in client.get("/login").text


def test_brand_assets_are_served(client):
    for path in ("favicon.svg", "favicon-32.png", "apple-touch-icon.png", "logo-light.svg", "logo-dark.svg", "mark.svg"):
        assert client.get(f"/static/brand/{path}").status_code == 200, path
    html = client.get("/login").text
    assert "/static/brand/favicon.svg" in html and "brand-mark" in html
