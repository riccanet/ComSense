"""NAT (port forwards, outbound, 1:1) and firewall rules from a firewall's newest backup, through the REST API
and the MCP server, for scripts and assistants checking firewalls."""
from __future__ import annotations

import gzip

import pytest
from conftest import auth, enroll, make_key
from sqlalchemy import select
from test_config_view import CONFIG

from app.models import Role, Task, TaskType
from app.services import apiops
from app.services.configview import one_to_one_nat_from_xml, outbound_nat_from_xml

OUTBOUND = b"""<outbound><mode>hybrid</mode>
  <rule><interface>wan</interface><protocol>any</protocol><source><network>192.168.50.0/24</network></source>
    <destination><any></any></destination><target>203.0.113.9</target><descr>Guest via .9</descr></rule>
  <rule><interface>wan</interface><source><network>10.0.0.0/8</network></source><destination><any></any></destination>
    <nonat></nonat><descr>No NAT to VPN</descr><disabled></disabled></rule></outbound>
  <onetoone><interface>wan</interface><external>203.0.113.20</external><source><address>192.168.1.20</address></source>
    <destination><any></any></destination><descr>Mail server</descr></onetoone>"""


def _with_outbound() -> bytes:
    return CONFIG.replace(b"<nat>", b"<nat>" + OUTBOUND, 1)


def test_outbound_and_one_to_one_are_read():
    xml = _with_outbound()
    out = outbound_nat_from_xml(xml)
    assert out["mode"] == "hybrid"
    assert out["rules"][0] | {} == {"interface": "wan", "protocol": "any", "source": "192.168.50.0/24",
                                    "source_port": "", "destination": "any", "destination_port": "",
                                    "translation": "203.0.113.9", "translation_port": "", "static_port": False,
                                    "disabled": False, "descr": "Guest via .9"}
    assert out["rules"][1]["translation"] == "none (no NAT)" and out["rules"][1]["disabled"]
    assert one_to_one_nat_from_xml(xml) == [{"interface": "wan", "external": "203.0.113.20", "internal": "192.168.1.20",
                                             "destination": "any", "disabled": False, "descr": "Mail server"}]
    assert outbound_nat_from_xml(CONFIG) == {"mode": "automatic", "rules": []}


def test_nat_and_rules_through_the_api(client, db, agent):
    creds = enroll(agent, make_key(db))
    did = creds["device_id"]
    _, value = apiops.create_key(db, "viewer", Role.viewer, "admin", None)
    db.commit()
    headers = {"Authorization": f"Bearer {value}"}
    assert client.get(f"/api/v1/firewalls/{did}/nat", headers=headers).status_code == 404  # no backup yet

    agent.post("/api/agent/v1/backups", content=gzip.compress(_with_outbound()), headers=auth(creds["token"]))
    nat = client.get(f"/api/v1/firewalls/{did}/nat", headers=headers).json()
    assert nat["firewall_id"] == did and nat["backup_id"]
    web = next(r for r in nat["port_forwards"] if r["port"] == "443")
    assert web["interface"] == "WAN" and web["target"] and "fingerprint" not in web
    assert nat["outbound_nat"]["mode"] == "hybrid" and len(nat["outbound_nat"]["rules"]) == 2
    assert nat["one_to_one"][0]["external"] == "203.0.113.20"

    rules = client.get(f"/api/v1/firewalls/{did}/rules", headers=headers).json()
    assert [r["descr"] for r in rules["rules"]][0] == "Default allow LAN to any rule"
    guest = client.get(f"/api/v1/firewalls/{did}/rules", params={"interface": "guest"}, headers=headers).json()
    assert guest["rules"] and all(r["interface"] == "Guest" for r in guest["rules"])
    assert rules["aliases"] and all(isinstance(a["entries"], list) and {"value", "note"} <= set(a["entries"][0])
                                    for a in rules["aliases"] if a["entries"])


@pytest.mark.changes
def test_port_forwards_added_changed_and_removed_through_the_api(client, db, agent):
    creds = enroll(agent, make_key(db))
    did = creds["device_id"]
    agent.post("/api/agent/v1/backups", content=gzip.compress(CONFIG), headers=auth(creds["token"]))
    keys = {}
    for role in (Role.viewer, Role.operator):
        keys[role] = {"Authorization": f"Bearer {apiops.create_key(db, role.value, role, 'admin', None)[1]}"}
    db.commit()
    forwards = client.get(f"/api/v1/firewalls/{did}/nat", headers=keys[Role.viewer]).json()["port_forwards"]
    web = next(r for r in forwards if not r["managed"])
    managed = next(r for r in forwards if r["managed"])

    body = {"port": "8443", "target": "192.168.1.30", "interface": "WAN", "description": "Camera"}
    assert client.post(f"/api/v1/firewalls/{did}/nat", json=body, headers=keys[Role.viewer]).status_code == 403
    r = client.post(f"/api/v1/firewalls/{did}/nat", json=body, headers=keys[Role.operator])
    assert r.status_code == 201 and r.json()["type"] == "nat_add", r.text
    add = db.scalar(select(Task).where(Task.type == TaskType.nat_add))
    assert add.payload["rule"] == {"interface": "wan", "protocol": "tcp", "source": {"any": True},
                                   "destination": {"network": "wanip", "port": "8443"}, "target": "192.168.1.30",
                                   "local_port": "8443", "descr": "Camera"}
    bad = client.post(f"/api/v1/firewalls/{did}/nat", json={"port": "80", "target": "not an ip!"},
                      headers=keys[Role.operator])
    assert bad.status_code == 400 and "target" in bad.json()["detail"]

    # A change keeps what is not given.
    r = client.patch(f"/api/v1/firewalls/{did}/nat/{web['id']}", json={"target": "192.168.1.99"},
                     headers=keys[Role.operator])
    assert r.status_code == 200, r.text
    edit = db.scalar(select(Task).where(Task.type == TaskType.nat_edit))
    assert edit.payload["fingerprint"] == web["id"] and edit.payload["rule"]["target"] == "192.168.1.99"
    assert edit.payload["rule"]["destination"]["port"] == web["port"] and edit.payload["rule"]["descr"] == web["descr"]

    assert client.patch(f"/api/v1/firewalls/{did}/nat/{managed['id']}", json={"disabled": True},
                        headers=keys[Role.operator]).status_code == 409  # from Configurations
    assert client.delete(f"/api/v1/firewalls/{did}/nat/0123456789abcdef", headers=keys[Role.operator]).status_code == 404
    assert client.delete(f"/api/v1/firewalls/{did}/nat/nope", headers=keys[Role.operator]).status_code == 400
    r = client.delete(f"/api/v1/firewalls/{did}/nat/{web['id']}", headers=keys[Role.operator])
    assert r.status_code == 200 and r.json()["type"] == "nat_remove"
    assert db.scalar(select(Task).where(Task.type == TaskType.nat_remove)).payload == {"fingerprint": web["id"],
                                                                                      "descr": web["descr"]}


def test_nat_changes_need_firewall_changes_on(client, db, agent):
    creds = enroll(agent, make_key(db))
    agent.post("/api/agent/v1/backups", content=gzip.compress(CONFIG), headers=auth(creds["token"]))
    headers = {"Authorization": f"Bearer {apiops.create_key(db, 'op', Role.operator, 'admin', None)[1]}"}
    db.commit()
    r = client.post(f"/api/v1/firewalls/{creds['device_id']}/nat", json={"port": "8443", "target": "192.168.1.30"},
                    headers=headers)
    assert r.status_code == 409 and "Coming soon" in r.json()["detail"]
