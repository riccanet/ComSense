from __future__ import annotations

import gzip

import pytest
from conftest import ALL_CAPS, auth, enroll, login, make_key
from sqlalchemy import select
from test_config_view import CONFIG

from app.models import Policy, PolicyType, Task, TaskType
from app.services.configview import port_forwards_from_xml


def _device(agent, db, caps=ALL_CAPS):
    creds = enroll(agent, make_key(db), capabilities=caps)
    agent.post("/api/agent/v1/backups", content=gzip.compress(CONFIG), headers=auth(creds["token"]))
    return creds["device_id"]


@pytest.mark.changes
def test_add_and_remove_port_forwards_from_the_firewall_page(client, db, agent):
    csrf = login(client)
    did = _device(agent, db)
    page = client.get(f"/devices/{did}").text
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
    assert "being added" in client.get(f"/devices/{did}").text
    r = client.post(f"/devices/{did}/nat", data={"dstport": "80", "target": "not-an-ip!", "csrf_token": csrf})
    assert "target must be an IP address or alias" in r.text

    client.post(f"/devices/{did}/nat/remove", data={"fingerprint": web["fingerprint"], "descr": "Web server",
                                                    "csrf_token": csrf})
    remove = db.scalar(select(Task).where(Task.type == TaskType.nat_remove))
    assert remove.payload == {"fingerprint": web["fingerprint"], "descr": "Web server"}
    assert "removal queued" in client.get(f"/devices/{did}").text
    assert client.post(f"/devices/{did}/nat/remove", data={"fingerprint": "x", "csrf_token": csrf}).status_code == 400


@pytest.mark.changes
def test_email_notifications_switch(client, db, agent):
    csrf = login(client)
    did = _device(agent, db)
    page = client.get(f"/devices/{did}").text
    assert "Email notifications" in page and "<strong>on</strong>" in page
    client.post(f"/devices/{did}/notifications", data={"smtp": "off", "csrf_token": csrf})
    task = db.scalar(select(Task).where(Task.type == TaskType.notifications))
    assert task.payload == {"smtp": False}
    assert "Turning off" in client.get(f"/devices/{did}").text


def test_changes_need_the_switch_and_the_firewall_permission(client, db, agent):
    csrf = login(client)
    did = _device(agent, db, caps=["backup"])
    page = client.get(f"/devices/{did}").text
    assert "Add a port forward to this firewall" not in page
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
