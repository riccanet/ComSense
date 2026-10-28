"""ARP entries and DHCP leases: stored from check-ins, shown on the firewall's Network page, and searchable
across every firewall by MAC (any notation), IP or hostname, in the console and the API."""
from __future__ import annotations

from conftest import auth, enroll, login, make_key

from app.models import Device, Role
from app.services import apiops
from app.services.neighbors import by_ip, mac_key, matches

NEIGHBORS = {
    "arp": [{"ip": "201.1.1.50", "mac": "a4:f8:ff:c8:67:32", "if": "mvneta1", "iface": "LAN", "hostname": "",
             "permanent": False, "expires": 1100},
            {"ip": "201.1.1.254", "mac": "00:08:a2:00:00:01", "if": "mvneta1", "iface": "LAN", "hostname": "",
             "permanent": True, "expires": None, "junk": "x" * 1000}],
    "leases": [{"ip": "201.1.1.50", "mac": "a4:f8:ff:c8:67:32", "hostname": "frontdesk-printer",
                "starts": "2026/10/28 10:00:00", "ends": "2026/10/28 12:00:00", "state": "active", "server": "isc"}],
    "static": [{"ip": "201.1.1.10", "mac": "00:11:22:33:44:55", "hostname": "nvr", "descr": "Cameras", "iface": "LAN"}],
    "collected": 1793150000,
}


def _firewall(agent, db, name, neighbors=None):
    creds = enroll(agent, make_key(db), system={"hostname": name, "unique_id": name})
    body = {"neighbors": neighbors} if neighbors is not None else {}
    agent.post("/api/agent/v1/checkin", json=body, headers=auth(creds["token"]))
    _firewall.tokens[creds["device_id"]] = creds["token"]
    return creds["device_id"]


_firewall.tokens = {}


def test_mac_matching():
    e = {"mac": "a4:f8:ff:c8:67:32", "ip": "201.1.1.50", "hostname": "frontdesk-printer"}
    for q in ("a4:f8:ff:c8:67:32", "A4-F8-FF-C8-67-32", "a4f8.ffc8.6732", "a4f8ffc86732", "67:32", "printer", "201.1.1.50"):
        assert matches(e, q), q
    assert not matches(e, "a4:f8:ff:c8:67:33") and mac_key("A4-F8") == "a4f8"
    assert [x["ip"] for x in by_ip([{"ip": "10.0.0.10"}, {"ip": ""}, {"ip": "10.0.0.9"}])] == ["10.0.0.9", "10.0.0.10", ""]


def test_reported_stored_shown_and_found(client, db, agent):
    login(client)
    sv = _firewall(agent, db, "fw-sv", NEIGHBORS)
    _firewall(agent, db, "fw-other", {"arp": [{"ip": "10.0.0.9", "mac": "de:ad:be:ef:00:01", "if": "igc0", "iface": "LAN"}]})
    quiet = _firewall(agent, db, "fw-old-agent")
    device = db.get(Device, sv)
    assert device.neighbors_at is not None and "junk" not in device.neighbors["arp"][1]
    # A later check-in without the section (it is sent every few minutes) keeps what was reported.
    agent.post("/api/agent/v1/checkin", json={"metrics": {"cpu_pct": 1}}, headers=auth(_firewall.tokens[sv]))
    db.expire_all()
    assert db.get(Device, sv).neighbors["leases"][0]["hostname"] == "frontdesk-printer"

    page = client.get(f"/devices/{sv}/network").text
    assert "frontdesk-printer" in page and "a4:f8:ff:c8:67:32" in page and "Cameras" in page
    filtered = client.get(f"/devices/{sv}/network?q=00-11-22").text
    assert "nvr" in filtered and "frontdesk-printer" not in filtered
    assert "has not reported its ARP table" in client.get(f"/devices/{quiet}/network").text

    # The firewall's overview lists its leases and finds a device by MAC in any notation, IP or name.
    overview = client.get(f"/devices/{sv}").text
    assert "DHCP leases" in overview and "frontdesk-printer" in overview
    found = client.get(f"/devices/{sv}?find=A4-F8-FF-C8-67-32").text
    assert "frontdesk-printer" in found and "Also in the ARP table" in found and "nvr" not in found
    missing = client.get(f"/devices/{sv}?find=ff:ff:ff:ff:ff:fe").text
    assert "No lease matches" in missing and "Not in this firewall's ARP table" in missing
    assert "Not reported yet" in client.get(f"/devices/{quiet}").text


def test_api_search_and_network(client, db, agent):
    sv = _firewall(agent, db, "fw-sv", NEIGHBORS)
    key, value = apiops.create_key(db, "viewer", Role.viewer, "admin", None)
    db.commit()
    headers = {"Authorization": f"Bearer {value}"}
    rows = client.get("/api/v1/devices/search", params={"q": "a4f8ffc86732"}, headers=headers).json()
    assert {(r["kind"], r["ip"]) for r in rows} == {("arp", "201.1.1.50"), ("leases", "201.1.1.50")}
    assert rows[0]["firewall"] == "fw-sv" and rows[0]["seen"]
    net = client.get(f"/api/v1/firewalls/{sv}/network", params={"q": "nvr"}, headers=headers).json()
    assert [s["ip"] for s in net["static"]] == ["201.1.1.10"] and net["leases"] == []
    assert client.get("/api/v1/devices/search", params={"q": "a"}, headers=headers).status_code == 422
