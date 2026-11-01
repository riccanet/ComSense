"""Any part of the configuration through the API and MCP: read as structured data (secrets hidden), edited as
operations on config paths (admin keys), never package settings, accounts or commands."""
from __future__ import annotations

import gzip

import pytest
from conftest import auth, enroll, make_key
from sqlalchemy import select
from test_config_view import CONFIG

from app.models import Role, Task, TaskType
from app.services import apiops
from app.services.configedit import ConfigEditError, validate_ops

SECRET = CONFIG.replace(b"</system>", b"<user><name>admin</name><bcrypt-hash>$2y$secret</bcrypt-hash></user></system>", 1)


def _setup(client, db, agent):
    creds = enroll(agent, make_key(db))
    agent.post("/api/agent/v1/backups", content=gzip.compress(SECRET), headers=auth(creds["token"]))
    keys = {}
    for role in (Role.viewer, Role.operator, Role.admin):
        keys[role] = {"Authorization": f"Bearer {apiops.create_key(db, role.value, role, 'admin', None)[1]}"}
    db.commit()
    return creds["device_id"], keys


def test_validation():
    ops = validate_ops([{"op": "set", "path": "/system/timezone/", "value": "UTC"},
                        {"op": "set", "path": "interfaces/opt1/enable", "value": True},
                        {"op": "set", "path": "interfaces/opt2/enable", "value": False},
                        {"op": "append", "path": "dhcpd/lan/staticmap", "value": {"mac": "x", "port": 80}}])
    assert ops == [{"op": "set", "path": "system/timezone", "value": "UTC"},
                   {"op": "set", "path": "interfaces/opt1/enable", "value": ""},
                   {"op": "delete", "path": "interfaces/opt2/enable"},
                   {"op": "append", "path": "dhcpd/lan/staticmap", "value": {"mac": "x", "port": "80"}}]
    for bad, msg in (([], "non-empty"), ([{"op": "chmod", "path": "x"}], "op must be"),
                     ([{"op": "set", "path": "installedpackages/pfblockerng", "value": "1"}], "cannot be edited"),
                     ([{"op": "set", "path": "system/user/0/name", "value": "x"}], "cannot be edited"),
                     ([{"op": "set", "path": "system/shellcmd", "value": "rm -rf /"}], "cannot be edited"),
                     ([{"op": "delete", "path": "cert/0"}], "cannot be edited"),
                     ([{"op": "set", "path": "../etc", "value": "x"}], "not a config path"),
                     ([{"op": "set", "path": "system/x"}], "needs a value"),
                     ([{"op": "set", "path": "ipsec/phase1/0", "value": {"pre-shared-key": "[hidden]"}}], "hidden")):
        with pytest.raises(ConfigEditError, match=msg):
            validate_ops(bad)


def test_read_any_part_with_secrets_hidden(client, db, agent):
    did, keys = _setup(client, db, agent)
    top = client.get(f"/api/v1/firewalls/{did}/config", headers=keys[Role.viewer]).json()
    assert {"system", "filter", "nat", "interfaces"} <= set(top["value"])
    system = client.get(f"/api/v1/firewalls/{did}/config", params={"path": "system"}, headers=keys[Role.viewer]).json()
    assert system["value"]["user"][0]["bcrypt-hash"] == "[hidden]" and system["editable"] is True
    rule = client.get(f"/api/v1/firewalls/{did}/config", params={"path": "filter/rule/0"}, headers=keys[Role.viewer]).json()
    assert rule["value"]["descr"] == "Default allow LAN to any rule"
    assert client.get(f"/api/v1/firewalls/{did}/config", params={"path": "nope/x"},
                      headers=keys[Role.viewer]).status_code == 404


@pytest.mark.changes
def test_edits_are_queued_for_admins_only(client, db, agent):
    did, keys = _setup(client, db, agent)
    body = {"operations": [{"op": "set", "path": "system/timezone", "value": "America/New_York"}],
            "summary": "Set the time zone"}
    for role in (Role.viewer, Role.operator):
        assert client.post(f"/api/v1/firewalls/{did}/config", json=body, headers=keys[role]).status_code == 403
    r = client.post(f"/api/v1/firewalls/{did}/config", json=body, headers=keys[Role.admin])
    assert r.status_code == 201 and r.json()["type"] == "config_edit", r.text
    task = db.scalar(select(Task).where(Task.type == TaskType.config_edit))
    assert task.payload == {"ops": [{"op": "set", "path": "system/timezone", "value": "America/New_York"}],
                            "summary": "Set the time zone"}
    bad = client.post(f"/api/v1/firewalls/{did}/config", headers=keys[Role.admin],
                      json={"operations": [{"op": "set", "path": "installedpackages/x", "value": "1"}]})
    assert bad.status_code == 400 and "cannot be edited" in bad.json()["detail"]
