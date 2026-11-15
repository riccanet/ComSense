"""VPN monitoring (the agent's "vpn" report), alerts, and connect / disconnect / reconnect."""
from __future__ import annotations

import time

import pytest
from conftest import ALL_CAPS, auth, csrf_from, enroll, login, make_key
from sqlalchemy import select
from test_api import _bearer, _key

from app.api import rest  # noqa: F401 - the REST app is built per test client
from app.models import Alert, Device, Role, Task, TaskStatus, TaskType, User
from app.security import hash_password
from app.services.alerts import VPN_GRACE, vpn_conditions

NOW = 1_800_000_000


def vpn_report(collected=NOW, ipsec_since=None, wg_since=None):
    ipsec_down = {"id": "2", "name": "Branch", "remote": "203.0.113.9", "status": "down", "children_expected": 1,
                  "children_up": 0}
    if ipsec_since is not None:
        ipsec_down["down_since"] = ipsec_since
    peer_down = {"id": "abcdef012345", "name": "Office", "endpoint": "office.example.net:51820", "keepalive": 25,
                 "status": "down", "handshake_age": None}
    if wg_since is not None:
        peer_down["down_since"] = wg_since
    return {
        "collected": collected,
        "ipsec": [
            {"id": "1", "name": "HQ", "remote": "198.51.100.1", "status": "up", "children_expected": 1, "children_up": 1},
            ipsec_down,
            {"id": "3", "name": "Mobile", "remote": "mobile clients", "status": "idle", "mobile": True},
            {"id": "4", "name": "Waits", "remote": "192.0.2.4", "status": "down", "responder": True},
            {"id": "5", "name": "Half", "remote": "192.0.2.5", "status": "partial", "children_expected": 2,
             "children_up": 1},
        ],
        "openvpn": [
            {"id": "server:1", "mode": "server", "vpnid": "1", "name": "Remote users", "status": "up", "clients": 1,
             "connections": [{"user": "alice", "remote": "203.0.113.50:51000", "client_id": "7",
                              "address": "10.8.0.2"}]},
            {"id": "client:2", "mode": "client", "vpnid": "2", "name": "To DC", "status": "down",
             "detail": "reconnecting; ping-restart"},
        ],
        "wireguard": [
            {"id": "tun_wg0", "name": "Sites", "interface": "tun_wg0", "interface_up": True, "status": "partial",
             "peers": [peer_down, {"id": "999999999999", "name": "Laptop", "endpoint": "", "keepalive": 0,
                                   "status": "idle"}]},
        ],
    }


def test_alerts_only_for_tunnels_that_stay_down():
    found = vpn_conditions(vpn_report())  # no down_since (an older report): alert at once
    assert set(found) == {"vpn:ipsec:2", "vpn:ipsec:5", "vpn:openvpn:client:2", "vpn:wireguard:tun_wg0:abcdef012345"}
    assert found["vpn:ipsec:2"][0] == "critical" and "203.0.113.9" in found["vpn:ipsec:2"][1]
    assert found["vpn:ipsec:5"][0] == "warning" and "1 of 2" in found["vpn:ipsec:5"][1]
    assert "reconnecting" in found["vpn:openvpn:client:2"][1]
    # Down for less than the grace period: not yet.
    recent = vpn_conditions(vpn_report(ipsec_since=NOW - 60, wg_since=NOW - VPN_GRACE + 1))
    assert "vpn:ipsec:2" not in recent and "vpn:wireguard:tun_wg0:abcdef012345" not in recent
    later = vpn_conditions(vpn_report(ipsec_since=NOW - 900, wg_since=NOW - VPN_GRACE))
    assert "for 15 minutes" in later["vpn:ipsec:2"][1] and "vpn:wireguard:tun_wg0:abcdef012345" in later
    assert vpn_conditions(None) == {} and vpn_conditions({"ipsec": "junk"}) == {}


def _device_with_vpn(agent, db, report=None):
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    r = agent.post("/api/agent/v1/checkin", json={"agent_version": "0.2.49", "vpn": report or vpn_report()},
                   headers=auth(creds["token"]))
    assert r.status_code == 200
    return creds


def test_checkin_stores_vpn_status_and_raises_alerts(client, db, agent):
    creds = _device_with_vpn(agent, db)
    db.expire_all()
    keys = {a.key for a in db.scalars(select(Alert).where(Alert.resolved_at.is_(None)))}
    assert {"vpn:ipsec:2", "vpn:openvpn:client:2"} <= keys
    # Back up: resolved.
    fixed = vpn_report()
    fixed["ipsec"][1]["status"] = "up"
    agent.post("/api/agent/v1/checkin", json={"vpn": fixed}, headers=auth(creds["token"]))
    db.expire_all()
    assert db.scalar(select(Alert).where(Alert.key == "vpn:ipsec:2")).resolved_at is not None


@pytest.mark.changes
def test_vpn_pages_and_controls(client, db, agent):
    creds = _device_with_vpn(agent, db)
    did = creds["device_id"]
    csrf = login(client)
    page = client.get(f"/devices/{did}").text
    assert f'href="/devices/{did}/vpn"' in page and "4 down" in page
    page = client.get(f"/devices/{did}/vpn").text
    for text in ("IPsec", "OpenVPN", "WireGuard", "HQ", "Branch", "alice", "Office", "responder"):
        assert text in page, text
    fleet = client.get("/vpn?show=problems").text
    assert "Branch" in fleet and "HQ" not in fleet

    def post(**data):
        return client.post(f"/devices/{did}/vpn", data={"csrf_token": csrf, **data}, follow_redirects=False)

    assert post(kind="ipsec", tunnel="2", action="reconnect").status_code == 303
    assert post(kind="openvpn", tunnel="server:1", action="kick", client="7").status_code == 303
    assert post(kind="wireguard", tunnel="tun_wg0", action="reconnect", peer="abcdef012345").status_code == 303
    # Refused: not reported, mobile, a peer without an endpoint, a user who left.
    post(kind="ipsec", tunnel="99", action="connect")
    post(kind="ipsec", tunnel="3", action="connect")
    post(kind="wireguard", tunnel="tun_wg0", action="reconnect", peer="999999999999")
    post(kind="openvpn", tunnel="server:1", action="kick", client="8")
    db.expire_all()
    tasks = db.scalars(select(Task).where(Task.type == TaskType.vpn_control).order_by(Task.id)).all()
    assert [t.payload["action"] for t in tasks] == ["reconnect", "kick", "reconnect"]
    assert tasks[0].payload == {"kind": "ipsec", "id": "2", "action": "reconnect", "name": "Branch"}
    assert tasks[1].payload["client"] == "7" and tasks[1].payload["user"] == "alice"
    assert tasks[2].payload["peer"] == "abcdef012345" and tasks[2].payload["name"] == "Office on Sites"

    # The agent's answer updates the page at once.
    task = tasks[0]
    task.status = TaskStatus.sent
    db.commit()
    now = vpn_report()
    now["ipsec"][1]["status"] = "up"
    agent.post(f"/api/agent/v1/tasks/{task.id}/result", json={"status": "success", "output": "Reconnect Branch: done.",
                                                                "result": {"vpn": now}}, headers=auth(creds["token"]))
    db.expire_all()
    assert db.get(Device, did).inventory["vpn"]["ipsec"][1]["status"] == "up"


def test_viewers_see_but_cannot_control(client, db, agent):
    did = _device_with_vpn(agent, db)["device_id"]
    db.add(User(username="viewer1", password_hash=hash_password("viewer-password-12"), role=Role.viewer))
    db.commit()
    csrf = login(client, "viewer1", "viewer-password-12")
    page = client.get(f"/devices/{did}/vpn").text
    assert "Branch" in page and 'name="action"' not in page
    r = client.post(f"/devices/{did}/vpn", data={"csrf_token": csrf, "kind": "ipsec", "tunnel": "2",
                                                 "action": "reconnect"})
    assert r.status_code == 403


@pytest.mark.changes
def test_api(client, db, agent):
    did = _device_with_vpn(agent, db)["device_id"]
    viewer, operator = _key(db), _key(db, Role.operator)
    r = client.get(f"/api/v1/firewalls/{did}/vpn", headers=_bearer(viewer))
    assert r.status_code == 200 and len(r.json()["tunnels"]) == 8 and r.json()["collected"] == NOW
    down = client.get("/api/v1/vpn?problems=true", headers=_bearer(viewer)).json()["tunnels"]
    assert {t["tunnel"] for t in down} == {"2", "5", "client:2", "tun_wg0"}
    body = {"type": "openvpn", "tunnel": "client:2", "action": "reconnect"}
    assert client.post(f"/api/v1/firewalls/{did}/vpn", json=body, headers=_bearer(viewer)).status_code == 403
    r = client.post(f"/api/v1/firewalls/{did}/vpn", json=body, headers=_bearer(operator))
    assert r.status_code == 201 and r.json()["type"] == "vpn_control"
    r = client.post(f"/api/v1/firewalls/{did}/vpn", json={**body, "tunnel": "client:9"}, headers=_bearer(operator))
    assert r.status_code == 400
    assert client.get(f"/api/v1/firewalls/{did}", headers=_bearer(viewer)).json()["vpn_summary"]["problems"] == 4


def test_old_agents_say_so(client, db, agent):
    creds = enroll(agent, make_key(db))
    login(client)
    assert "has not reported its VPN status yet" in client.get(f"/devices/{creds['device_id']}/vpn").text
    assert time.time() > 0
