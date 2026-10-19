from __future__ import annotations

import gzip
import re

import pytest
from conftest import ALL_CAPS, auth, enroll, login, make_key
from sqlalchemy import select
from test_config_view import CONFIG

from app.models import Device, Organization, Policy, PolicyAssignment, PolicyType, Task, TaskType
from app.services.configview import aliases_from_xml, port_forwards_from_xml


def _device(agent, db, caps=ALL_CAPS):
    creds = enroll(agent, make_key(db), capabilities=caps)
    agent.post("/api/agent/v1/backups", content=gzip.compress(CONFIG), headers=auth(creds["token"]))
    return creds["device_id"]


@pytest.mark.changes
def test_add_and_remove_port_forwards_from_the_firewall_page(client, db, agent):
    csrf = login(client)
    did = _device(agent, db)
    page = client.get(f"/devices/{did}/configuration").text
    web, rdp = port_forwards_from_xml(CONFIG)
    assert f'value="{web["fingerprint"]}"' in page  # a Remove button for the local one
    assert f'value="{rdp["fingerprint"]}"' not in page  # the [CSFM] one is managed in Configurations
    assert "Add a port forward to this firewall" in page

    client.post(f"/devices/{did}/nat", data={"interface": "wan", "protocol": "tcp", "dstport": "8443",
                                             "target": "192.168.1.30", "localport": "", "descr": "Camera",
                                             "csrf_token": csrf})
    add = db.scalar(select(Task).where(Task.type == TaskType.nat_add))
    assert add.payload["rule"] == {"interface": "wan", "protocol": "tcp", "source": {"any": True},
                                   "destination": {"network": "wanip", "port": "8443"}, "target": "192.168.1.30",
                                   "local_port": "8443", "descr": "Camera"}
    assert "being added" in client.get(f"/devices/{did}/configuration").text
    r = client.post(f"/devices/{did}/nat", data={"dstport": "80", "target": "not-an-ip!", "csrf_token": csrf})
    assert "target must be an IP address or alias" in r.text

    client.post(f"/devices/{did}/nat/remove", data={"fingerprint": web["fingerprint"], "descr": "Web server",
                                                    "csrf_token": csrf})
    remove = db.scalar(select(Task).where(Task.type == TaskType.nat_remove))
    assert remove.payload == {"fingerprint": web["fingerprint"], "descr": "Web server"}
    assert "removal queued" in client.get(f"/devices/{did}/configuration").text
    assert client.post(f"/devices/{did}/nat/remove", data={"fingerprint": "x", "csrf_token": csrf}).status_code == 400


@pytest.mark.changes
def test_edit_a_port_forward_from_the_firewall_page(client, db, agent):
    csrf = login(client)
    did = _device(agent, db)
    web, rdp = port_forwards_from_xml(CONFIG)
    page = client.get(f"/devices/{did}/configuration").text
    assert f"edit_nat={web['fingerprint']}" in page and f"edit_nat={rdp['fingerprint']}" not in page
    form = client.get(f"/devices/{did}/configuration?edit_nat={web['fingerprint']}").text
    assert 'action="/devices/' + did + '/nat/edit"' in form
    assert 'value="192.168.1.10"' in form and 'value="8443"' in form and 'value="Web server"' in form
    # A configuration's port forward has no edit form.
    assert "/nat/edit" not in client.get(f"/devices/{did}/configuration?edit_nat={rdp['fingerprint']}").text

    client.post(f"/devices/{did}/nat/edit", data={
        "fingerprint": web["fingerprint"], "interface": "wan", "protocol": "tcp", "src": "", "dst": "wan address",
        "dstport": "443", "target": "192.168.1.11", "localport": "443", "descr": "Web server", "disabled": "true",
        "csrf_token": csrf})
    edit = db.scalar(select(Task).where(Task.type == TaskType.nat_edit))
    assert edit.payload == {"fingerprint": web["fingerprint"], "rule": {
        "interface": "wan", "protocol": "tcp", "source": {"any": True},
        "destination": {"network": "wanip", "port": "443"}, "target": "192.168.1.11", "local_port": "443",
        "descr": "Web server", "disabled": True}}
    assert "change queued" in client.get(f"/devices/{did}/configuration").text

    r = client.post(f"/devices/{did}/nat/edit", data={"fingerprint": web["fingerprint"], "dstport": "443",
                                                      "target": "bad ip!", "csrf_token": csrf})
    assert "target must be an IP address or alias" in r.text
    assert client.post(f"/devices/{did}/nat/edit", data={"fingerprint": "x", "dstport": "1", "target": "1.1.1.1",
                                                         "csrf_token": csrf}).status_code == 400


def test_configuration_page_layout(client, db, agent):
    login(client)
    did = _device(agent, db)
    main = client.get(f"/devices/{did}").text
    assert f'href="/devices/{did}/configuration"' in main and ">View config<" not in main
    assert "Inbound NAT policies" not in main and "<h2>Services" not in main and "<h2>Settings" not in main
    page = client.get(f"/devices/{did}/configuration").text
    for heading in ("<h2>Aliases</h2>", "<h2>Inbound NAT policies</h2>", "<h2>Services", "<h2>Email notifications</h2>",
                    "<h2>Notes</h2>"):
        assert heading in page, heading
    assert f'href="/devices/{did}/config"' in page and ">View<" in page
    assert "Web_Servers" in page and "Primary" in page


def test_aliases_are_read_from_config_xml():
    by_name = {a["name"]: a for a in aliases_from_xml(CONFIG)}
    office, web = by_name["Office"], by_name["Web_Servers"]
    assert web["entry_list"] == [{"value": "192.168.1.10", "note": "Primary"}, {"value": "192.168.1.11", "note": "Standby"}]
    assert web["entries"] == "192.168.1.10 Primary\n192.168.1.11 Standby" and office["type"] == "network"


@pytest.mark.changes
def test_add_edit_and_remove_aliases_from_the_configuration_page(client, db, agent):
    csrf = login(client)
    did = _device(agent, db)
    form = client.get(f"/devices/{did}/configuration?edit_alias=Web_Servers").text
    assert 'action="/devices/' + did + '/aliases/edit"' in form and "192.168.1.11 Standby" in form

    r = client.post(f"/devices/{did}/aliases", data={"name": "Cameras", "type": "host",
                                                    "entries": "192.168.1.40 Door\n192.168.1.41", "descr": "CCTV",
                                                    "csrf_token": csrf})
    assert r.url.path == f"/devices/{did}/configuration"
    add = db.scalar(select(Task).where(Task.type == TaskType.alias_add))
    assert add.payload == {"alias": {"name": "Cameras", "type": "host", "address": ["192.168.1.40", "192.168.1.41"],
                                     "descr": "CCTV", "detail": ["Door", ""]}}
    assert "being added" in r.text

    client.post(f"/devices/{did}/aliases/edit", data={"name": "Web_Servers", "type": "host",
                                                     "entries": "192.168.1.12", "descr": "Front end", "csrf_token": csrf})
    edit = db.scalar(select(Task).where(Task.type == TaskType.alias_edit))
    assert edit.payload["alias"] == {"name": "Web_Servers", "type": "host", "address": ["192.168.1.12"],
                                     "descr": "Front end"}
    assert "change queued" in client.get(f"/devices/{did}/configuration").text

    client.post(f"/devices/{did}/aliases/remove", data={"name": "Office", "csrf_token": csrf})
    assert db.scalar(select(Task).where(Task.type == TaskType.alias_remove)).payload == {"name": "Office"}
    assert "removal queued" in client.get(f"/devices/{did}/configuration").text

    for bad, message in (({"name": "bad name!", "entries": "1.2.3.4"}, "name is invalid"),
                         ({"name": "X", "entries": "999.1.1.1"}, "is not an address"),
                         ({"name": "P", "type": "port", "entries": "http"}, None),
                         ({"name": "P2", "type": "port", "entries": "80-90"}, "is not a port")):
        r = client.post(f"/devices/{did}/aliases", data={"type": "host", **bad, "csrf_token": csrf})
        if message:
            assert message in r.text, (bad, r.text[-2000:])
    assert client.post(f"/devices/{did}/aliases/remove", data={"name": "a b", "csrf_token": csrf}).status_code == 400


@pytest.mark.changes
def test_aliases_from_configurations_are_not_editable_here(client, db, agent):
    login(client)
    did = _device(agent, db)
    policy = Policy(name="Shared", type=PolicyType.aliases,
                    content={"aliases": [{"name": "Office", "type": "network", "address": ["10.0.0.0/24"]}]})
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, device_id=did))
    db.commit()
    page = client.get(f"/devices/{did}/configuration").text
    assert "edit_alias=Web_Servers" in page and "edit_alias=Office" not in page


def test_firewall_rules_by_interface(client, db, agent):
    login(client)
    did = _device(agent, db)
    page = client.get(f"/devices/{did}/configuration").text
    tabs = re.findall(r'\?rules=(\w+)#rules"[^>]*>([^<]+)<span class="muted small">(\d+)', page)
    assert [(t, n.strip(), c) for t, n, c in tabs] == [("floating", "Floating", "1"), ("wan", "WAN", "1"),
                                                       ("lan", "LAN", "1"), ("opt1", "Guest", "1")]
    assert "Default allow LAN to any rule" in page and "No SMB from guests" not in page  # opens on LAN
    guest = client.get(f"/devices/{did}/configuration?rules=opt1").text
    assert "No SMB from guests" in guest and "rule-block" in guest and "445" in guest
    wan = client.get(f"/devices/{did}/configuration?rules=wan").text
    assert ">NAT</span>" in wan and "s-disabled" in wan
    floating = client.get(f"/devices/{did}/configuration?rules=floating").text
    assert "Block bad hosts" in floating and "WAN, LAN" in floating


def test_package_aliases_are_tucked_away(client, db, agent):
    login(client)
    did = _device(agent, db)
    page = client.get(f"/devices/{did}/configuration").text
    main, _, system = page.partition("Aliases added by packages (1)")
    assert "pfB_PRI1_v4" not in main and "pfB_PRI1_v4" in system and "edit_alias=pfB_" not in page
    header = re.search(r"<table class=\"aliases\">\s*<thead><tr>(.*?)</tr>", page, re.S).group(1)
    assert re.findall(r"<th[^>]*>(\w*)</th>", header) == ["Name", "Type", "Description", "Entries", ""]


@pytest.mark.changes
def test_packages_on_the_configuration_page(client, db, agent):
    csrf = login(client)
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    agent.post("/api/agent/v1/checkin", json={"packages": [{"name": "pfSense-pkg-ComSense", "version": "0.2.7"},
                                                            {"name": "pfSense-pkg-Netgate_Firmware_Upgrade", "version": "1.2"}]},
               headers=auth(creds["token"]))
    did = creds["device_id"]
    assert "<h2>Packages" not in client.get(f"/devices/{did}").text
    page = client.get(f"/devices/{did}/configuration").text
    assert "<h2>Packages</h2>" in page and "this agent" in page
    assert 'value="pfSense-pkg-Netgate_Firmware_Upgrade"' in page and 'value="pfSense-pkg-ComSense"' not in page
    r = client.post(f"/devices/{did}/tasks", data={"task_type": "remove_package",
                                                   "package": "pfSense-pkg-Netgate_Firmware_Upgrade", "csrf_token": csrf})
    assert r.url.path == f"/devices/{did}/configuration" and "removal queued" in r.text
    task = db.scalar(select(Task).where(Task.type == TaskType.remove_package))
    assert task.payload == {"package": "pfSense-pkg-Netgate_Firmware_Upgrade"}
    r = client.post(f"/devices/{did}/tasks", data={"task_type": "remove_package", "package": "pfSense-pkg-ComSense",
                                                   "csrf_token": csrf})
    assert "cannot remove itself" in r.text


def test_notes_keep_the_name_and_customer(client, db, agent):
    csrf = login(client)
    did = _device(agent, db)
    org = Organization(name="Acme")
    db.add(org)
    db.commit()
    device = db.get(Device, did)
    device.organization_id, name = org.id, device.name
    db.commit()
    page = client.get(f"/devices/{did}/configuration").text
    notes = page[page.index('id="notes"'):]
    assert 'name="name"' not in notes and 'name="organization_id"' not in notes
    client.post(f"/devices/{did}/edit", data={"notes": "Rack 3", "csrf_token": csrf})
    db.expire_all()
    device = db.get(Device, did)
    assert (device.notes, device.name, device.organization_id) == ("Rack 3", name, org.id)


@pytest.mark.changes
def test_email_notifications_switch(client, db, agent):
    csrf = login(client)
    did = _device(agent, db)
    page = client.get(f"/devices/{did}/configuration").text
    assert "Email notifications" in page and "<strong>on</strong>" in page
    client.post(f"/devices/{did}/notifications", data={"smtp": "off", "csrf_token": csrf})
    task = db.scalar(select(Task).where(Task.type == TaskType.notifications))
    assert task.payload == {"smtp": False}
    assert "Turning off" in client.get(f"/devices/{did}/configuration").text


@pytest.mark.changes
def test_configuration_page_says_when_the_firewall_does_not_allow_changes(client, db, agent):
    login(client)
    did = _device(agent, db, caps=["backup"])
    page = client.get(f"/devices/{did}/configuration").text
    assert "change or remove aliases from here" in page and "change or remove port forwards from here" in page
    assert "Add an alias to this firewall" not in page


def test_changes_need_the_switch_and_the_firewall_permission(client, db, agent):
    csrf = login(client)
    did = _device(agent, db, caps=["backup"])
    page = client.get(f"/devices/{did}/configuration").text
    assert "Add a port forward to this firewall" not in page
    assert page.count("Firewall changes are turned off on this server.") == 3
    r = client.post(f"/devices/{did}/notifications", data={"smtp": "off", "csrf_token": csrf})
    assert db.scalar(select(Task).where(Task.type == TaskType.notifications)) is None
    assert r.status_code == 200


def test_notifications_configuration(client, db):
    csrf = login(client)
    assert "New notification setting" in client.get("/configurations/notifications").text
    client.post("/configurations", data={"type": "notifications", "name": "Quiet sites", "smtp": "off",
                                         "csrf_token": csrf})
    policy = db.scalar(select(Policy).where(Policy.name == "Quiet sites"))
    assert policy.type == PolicyType.notifications and policy.content == {"smtp": False}
    assert "Quiet sites" in client.get("/configurations/notifications").text
