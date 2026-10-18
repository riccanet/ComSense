from __future__ import annotations

import pytest
from conftest import SYSTEM, csrf_from, enroll, login, make_key
from sqlalchemy import select

from app.models import Device, DeviceGroup, Policy, PolicyAssignment, PolicyType, Role, User
from app.security import hash_password
from app.services.policies import desired_policies
from app.web.config_routes import endpoint_text, parse_endpoint


@pytest.mark.parametrize("text, ep", [
    ("any", {"any": True}),
    ("", {"any": True}),
    ("lan net", {"network": "lan"}),
    ("wan address", {"network": "wanip"}),
    ("this firewall", {"network": "(self)"}),
    ("10.0.0.0/24", {"address": "10.0.0.0/24"}),
    ("Office_Hosts", {"address": "Office_Hosts"}),
    ("!opt1 net", {"network": "opt1", "not": True}),
])
def test_endpoint_text_round_trip(text, ep):
    assert parse_endpoint(text) == ep
    assert endpoint_text(ep) == (text or "any")


def _create(client, csrf, data):
    return client.post("/configurations", data={"csrf_token": csrf, **data}, follow_redirects=False)


def test_alias_rule_and_nat_forms(client, db):
    csrf = login(client)
    r = _create(client, csrf, {
        "type": "aliases", "name": "Office",
        "a_row": ["1", "2"], "a_name": ["Office_Hosts", "Web_Ports"], "a_type": ["host", "port"],
        "a_address": ["10.0.0.5 Printer\n10.0.0.6", "80, 443"], "a_descr": ["Office", ""],
    })
    assert r.status_code == 303
    aliases = db.scalar(select(Policy).where(Policy.name == "Office"))
    assert aliases.content["aliases"][0] == {"name": "Office_Hosts", "type": "host", "address": ["10.0.0.5", "10.0.0.6"],
                                             "detail": ["Printer", ""], "descr": "Office"}
    assert aliases.content["aliases"][1]["address"] == ["80", "443"]
    page = client.get(f"/configurations/{aliases.id}").text
    assert "10.0.0.5 Printer\n10.0.0.6" in page

    r = _create(client, csrf, {
        "type": "firewall_rules", "name": "Mgmt", "position": "bottom",
        "r_row": ["1", "2"], "r_interface": ["WAN", "lan"], "r_type": ["pass", "block"],
        "r_ipprotocol": ["inet", "inet"], "r_protocol": ["tcp", "any"],
        "r_src": ["Office_Hosts", "any"], "r_srcport": ["", ""], "r_dst": ["wan address", "!lan net"],
        "r_dstport": ["443", ""], "r_descr": ["GUI", "Block"], "r_log": ["2"], "r_disabled": [],
    })
    assert r.status_code == 303
    rules = db.scalar(select(Policy).where(Policy.name == "Mgmt")).content
    assert rules["position"] == "bottom"
    assert rules["rules"][0] == {"interface": "wan", "type": "pass", "ipprotocol": "inet", "protocol": "tcp",
                                 "source": {"address": "Office_Hosts"},
                                 "destination": {"network": "wanip", "port": "443"}, "descr": "GUI"}
    assert rules["rules"][1]["log"] is True and rules["rules"][1]["destination"] == {"network": "lan", "not": True}

    r = _create(client, csrf, {
        "type": "port_forward", "name": "Web",
        "n_row": ["1"], "n_interface": ["wan"], "n_protocol": ["tcp"], "n_src": [""], "n_dst": [""],
        "n_dstport": ["8443"], "n_target": ["192.168.1.10"], "n_localport": [""], "n_descr": ["Web"],
        "n_disabled": ["1"],
    })
    assert r.status_code == 303
    nat = db.scalar(select(Policy).where(Policy.name == "Web"))
    assert nat.type == PolicyType.port_forward
    assert nat.content["rules"][0] == {"interface": "wan", "protocol": "tcp", "source": {"any": True},
                                       "destination": {"network": "wanip", "port": "8443"},
                                       "target": "192.168.1.10", "local_port": "8443", "descr": "Web",
                                       "disabled": True}
    for section, name in (("aliases", "Office"), ("rules", "Mgmt"), ("nat", "Web")):
        assert name in client.get(f"/configurations/{section}").text

    # Validation errors keep the form and say what is wrong.
    r = _create(client, csrf, {"type": "port_forward", "name": "Bad", "n_row": ["1"], "n_interface": ["wan"],
                               "n_protocol": ["tcp"], "n_src": [""], "n_dst": [""], "n_dstport": ["80"],
                               "n_target": ["not an ip!"], "n_localport": [""], "n_descr": ["x"]})
    assert r.status_code == 400 and "target must be an IP address or alias" in r.text

    # Editing bumps the revision only when the content changes.
    page = client.get(f"/configurations/{nat.id}").text
    client.post(f"/configurations/{nat.id}", data={
        "csrf_token": csrf_from(page), "name": "Web", "enabled": "true", "type": "port_forward",
        "n_row": ["1"], "n_interface": ["wan"], "n_protocol": ["tcp"], "n_src": [""], "n_dst": ["wan address"],
        "n_dstport": ["8443"], "n_target": ["192.168.1.11"], "n_localport": ["443"], "n_descr": ["Web"],
    })
    db.expire_all()
    nat = db.get(Policy, nat.id)
    assert nat.revision == 2 and nat.content["rules"][0]["target"] == "192.168.1.11"


def test_firewall_groups_drive_assignments(client, db, agent):
    csrf = login(client)
    a = enroll(agent, make_key(db))
    b = enroll(agent, make_key(db), system={**SYSTEM, "unique_id": "b"})
    policy = Policy(name="fwd", type=PolicyType.port_forward, content={"rules": [{
        "destination": {"network": "wanip", "port": "80"}, "target": "10.0.0.1", "local_port": "80"}]})
    db.add(policy)
    db.commit()

    r = client.post("/configurations/groups", data={"name": "Branches", "csrf_token": csrf}, follow_redirects=False)
    group = db.scalar(select(DeviceGroup))
    assert r.headers["location"] == f"/configurations/groups/{group.id}"
    client.post(f"/configurations/groups/{group.id}", data={"name": "Branches", "device_ids": [a["device_id"]],
                                                            "csrf_token": csrf})
    client.post(f"/configurations/{policy.id}/assign", data={"target": f"group:{group.id}", "csrf_token": csrf})
    r = client.post(f"/configurations/{policy.id}/assign", data={"target": f"group:{group.id}", "csrf_token": csrf})
    assert "already exists" in r.text
    db.expire_all()
    assert [p.name for p in desired_policies(db, db.get(Device, a["device_id"]))] == ["fwd"]
    assert desired_policies(db, db.get(Device, b["device_id"])) == []
    assert "Branches" in client.get(f"/devices/{a['device_id']}").text
    assert "fwd" in client.get(f"/configurations/groups/{group.id}").text

    # Membership changes move the configuration with them.
    client.post(f"/configurations/groups/{group.id}", data={"name": "Branches", "device_ids": [b["device_id"]],
                                                            "csrf_token": csrf})
    db.expire_all()
    assert desired_policies(db, db.get(Device, a["device_id"])) == []
    assert [p.name for p in desired_policies(db, db.get(Device, b["device_id"]))] == ["fwd"]

    client.post(f"/configurations/groups/{group.id}/delete", data={"csrf_token": csrf})
    db.expire_all()
    assert db.scalar(select(PolicyAssignment)) is None
    assert desired_policies(db, db.get(Device, b["device_id"])) == []


def test_viewers_can_look_but_not_change(client, db):
    db.add(Policy(name="ro", type=PolicyType.aliases, content={"aliases": [{"name": "X", "type": "host", "address": []}]}))
    db.add(User(username="v", password_hash=hash_password("viewer-password-1"), role=Role.viewer))
    db.commit()
    csrf = login(client, "v", "viewer-password-1")
    page = client.get("/configurations/aliases").text
    assert "ro" in page and "/configurations/new" not in page
    pid = db.scalar(select(Policy.id))
    assert "<fieldset class=\"plain\" disabled>" in client.get(f"/configurations/{pid}").text
    assert client.post("/configurations", data={"type": "aliases", "name": "n", "csrf_token": csrf}).status_code == 403
    assert client.post("/configurations/groups", data={"name": "g", "csrf_token": csrf}).status_code == 403
    assert client.get("/policies", follow_redirects=False).headers["location"] == "/configurations/aliases"
