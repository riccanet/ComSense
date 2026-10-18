from __future__ import annotations

import re

from conftest import login

SECTIONS = ["/settings/email", "/settings/alerts", "/settings/addresses", "/settings/setup"]


def test_settings_sections_have_their_own_pages_with_left_navigation(client):
    csrf = login(client)
    assert client.get("/settings", follow_redirects=False).headers["location"] == "/settings/email"
    for path in SECTIONS:
        page = client.get(path).text
        nav = re.search(r'<nav class="settings-nav".*?</nav>', page, re.S).group(0)
        assert all(f'href="{p}"' in nav for p in SECTIONS), path
        assert re.search(rf'href="{path}" class="active" aria-current="page"', nav), path
    assert 'action="/settings/email"' in client.get("/settings/email").text
    assert 'action="/settings/alerts"' in client.get("/settings/alerts").text
    assert 'name="trusted_proxies"' in client.get("/settings/addresses").text
    assert 'href="/setup"' in client.get("/settings/setup").text
    # Each form returns to its own page.
    r = client.post("/settings/alerts", data={"min_severity": "warning", "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == "/settings/alerts"
    r = client.post("/settings/agent-network", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == "/settings/addresses"
    r = client.post("/settings/email", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == "/settings/email"


def test_settings_pages_are_admin_only(client, db):
    from app.models import Role, User
    from app.security import hash_password

    db.add(User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator))
    db.commit()
    login(client, "op", "operator-password-1")
    for path in ["/settings", *SECTIONS]:
        assert client.get(path, follow_redirects=False).status_code == 403, path
