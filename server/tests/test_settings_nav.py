from __future__ import annotations

import re

from conftest import login

SECTIONS = ["/settings/general", "/users", "/keys", "/settings/email", "/settings/alerts", "/settings/addresses",
            "/settings/setup"]


def test_settings_sections_have_their_own_pages_with_left_navigation(client):
    csrf = login(client)
    assert client.get("/settings", follow_redirects=False).headers["location"] == "/settings/general"
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


def test_users_and_keys_moved_to_settings(client):
    login(client)
    top = re.search(r'<header class="topbar">.*?<div class="who">', client.get("/devices").text, re.S).group(0)
    assert 'href="/users"' not in top and 'href="/keys"' not in top
    for path in ("/users", "/keys"):
        page = client.get(path).text
        assert 'class="icon-btn active"' in page, path  # the Settings gear is highlighted


def test_time_zone_setting(client, db):
    from datetime import datetime, timezone

    from app.services.appsettings import format_dt, get_site_settings

    csrf = login(client)
    page = client.get("/settings/general").text
    assert '<option value="America/Chicago"' in page and "UTC" in page
    client.post("/settings/general", data={"timezone": "Mars/Base", "csrf_token": csrf}, follow_redirects=False)
    db.expire_all()
    assert get_site_settings(db).timezone == "UTC"
    client.post("/settings/general", data={"timezone": "America/Chicago", "csrf_token": csrf})
    db.expire_all()
    assert get_site_settings(db).timezone == "America/Chicago"
    assert format_dt(datetime(2026, 7, 1, 17, 30, tzinfo=timezone.utc)) == "2026-07-01 12:30 PM CDT"
    assert format_dt(datetime(2026, 1, 1, 17, 30, tzinfo=timezone.utc)) == "2026-01-01 11:30 AM CST"
    assert 'value="America/Chicago" selected' in client.get("/settings/general").text


def test_times_use_a_12_hour_clock(db):
    from datetime import datetime, timezone

    from app.services.appsettings import format_dt

    utc = timezone.utc
    assert format_dt(datetime(2026, 10, 18, 0, 5, tzinfo=utc)) == "2026-10-18 12:05 AM UTC"
    assert format_dt(datetime(2026, 10, 18, 9, 7, tzinfo=utc)) == "2026-10-18 9:07 AM UTC"
    assert format_dt(datetime(2026, 10, 18, 12, 0, tzinfo=utc)) == "2026-10-18 12:00 PM UTC"
    assert format_dt(datetime(2026, 10, 18, 23, 59, tzinfo=utc)) == "2026-10-18 11:59 PM UTC"


def test_new_buttons_open_the_add_forms(client):
    login(client)
    users = client.get("/users").text
    assert 'href="#new-user"' in users and 'id="new-user"' in users and 'action="/users"' in users
    customers = client.get("/customers").text
    assert 'href="#new-customer"' in customers and 'id="new-customer"' in customers
