from __future__ import annotations

import re

import pytest
from conftest import login

from app.enrollment import parse_code
from app.services.appsettings import get_agent_network_settings, normalize_agent_url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        ("agents.example.com", "https://agents.example.com:10443"),
        ("agents.example.com:9443", "https://agents.example.com:9443"),
        ("https://Agents.Example.com/", "https://agents.example.com:10443"),
        ("203.0.113.10:443", "https://203.0.113.10:443"),
        ("[2001:db8::5]:9443", "https://[2001:db8::5]:9443"),
    ],
)
def test_normalize_agent_url(value, expected):
    assert normalize_agent_url(value, 10443) == expected


@pytest.mark.parametrize(
    "value", ["http://agents.example.com", "agents.example.com/path", "bad host", "host:99999", "-x.example.com", ":10443"]
)
def test_normalize_agent_url_rejects(value):
    with pytest.raises(ValueError):
        normalize_agent_url(value, 10443)


def _new_code(client, csrf: str) -> str:
    client.post("/keys", data={"name": "k", "expires_days": "7", "csrf_token": csrf}, follow_redirects=False)
    page = client.get("/keys").text
    return re.search(r'value="(csfm1\.[^"]+)"', page).group(1)


def test_agent_address_from_settings_page_goes_into_enrollment_codes(client, db, settings):
    csrf = login(client)
    assert parse_code(_new_code(client, csrf))["url"] == settings.agent_url

    page = client.get("/settings").text
    assert settings.agent_url in page  # shown as the default

    r = client.post(
        "/settings/agent-network",
        data={"agent_url": "agents.example.com:9443", "trusted_proxies": "100.64.0.0/10", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303
    db.expire_all()
    cfg = get_agent_network_settings(db)
    assert cfg.agent_url == "https://agents.example.com:9443" and cfg.trusted_proxies == ["100.64.0.0/10"]
    assert "https://agents.example.com:9443" in client.get("/keys").text
    assert parse_code(_new_code(client, csrf))["url"] == "https://agents.example.com:9443"

    # A bad address is refused and the saved one kept.
    client.post("/settings/agent-network", data={"agent_url": "http://x", "csrf_token": csrf})
    db.expire_all()
    assert get_agent_network_settings(db).agent_url == "https://agents.example.com:9443"

    # Clearing it goes back to the default.
    client.post("/settings/agent-network", data={"agent_url": "", "csrf_token": csrf})
    assert parse_code(_new_code(client, csrf))["url"] == settings.agent_url
