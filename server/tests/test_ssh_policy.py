"""Configurations > SSH: SSH access on every assigned firewall."""
from __future__ import annotations

import pytest
from conftest import login
from sqlalchemy import select

from app.models import Policy, PolicyType
from app.services.policies import PolicyError, validate_policy

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINocKeyNocKeyNocKeyNocKeyNocKeyNocKey12 noc@example.com"


def test_ssh_content_is_validated():
    validate_policy(PolicyType.ssh, {"enabled": True, "port": 22, "auth": "password_or_key", "agent_forwarding": False,
                                     "admin_keys": []})
    validate_policy(PolicyType.ssh, {"enabled": True, "port": 2222, "auth": "key_only", "admin_keys": [KEY]})
    validate_policy(PolicyType.ssh, {"enabled": False})
    for bad, why in (({"enabled": "yes"}, "enabled"), ({"enabled": True, "port": 0}, "port"),
                     ({"enabled": True, "auth": "telnet"}, "auth"), ({"enabled": True, "admin_keys": ["not a key"]}, "OpenSSH"),
                     ({"enabled": True, "auth": "key_only"}, "key-only"), ({"enabled": True, "shell": 1}, "unknown")):
        with pytest.raises(PolicyError, match=why):
            validate_policy(PolicyType.ssh, bad)


def test_ssh_configuration_from_the_form(client, db):
    csrf = login(client)
    page = client.get("/configurations/ssh").text
    assert "New SSH setting" in page and "Secure Shell" in page
    assert "Login with" in client.get("/configurations/new?type=ssh").text
    r = client.post("/configurations", data={"type": "ssh", "name": "SSH everywhere", "enabled": "on", "port": "22",
                                             "auth": "key_only", "admin_keys": f"\n{KEY}\n\n", "csrf_token": csrf})
    assert r.status_code == 200
    policy = db.scalar(select(Policy).where(Policy.type == PolicyType.ssh))
    assert policy.content == {"enabled": True, "port": 22, "auth": "key_only", "agent_forwarding": False, "admin_keys": [KEY]}
    assert "On, port 22, 1 key(s)" in client.get("/configurations/ssh").text
    r = client.post("/configurations", data={"type": "ssh", "name": "Locked out", "enabled": "on", "port": "22",
                                             "auth": "key_only", "admin_keys": "", "csrf_token": csrf})
    assert "key-only login" in r.text
    assert db.scalar(select(Policy).where(Policy.name == "Locked out")) is None
