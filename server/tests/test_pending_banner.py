from __future__ import annotations

from conftest import enroll, login, make_key
from sqlalchemy import select

from app.models import Device, DeviceStatus, Role, User
from app.security import hash_password


def test_admins_see_new_firewalls_waiting_for_approval(client, db, agent):
    csrf = login(client)
    assert "is waiting for approval" not in client.get("/customers").text
    creds = enroll(agent, make_key(db, require_approval=True), system={"hostname": "new-fw", "unique_id": "n1"})
    did = creds["device_id"]

    page = client.get("/customers").text  # on every page, under the navigation bar
    assert "New firewall:" in page and "new-fw" in page and "is waiting for approval" in page
    assert 'name="action" value="approve"' in page and 'name="next" value="/customers"' in page
    # The banner alone, which the page fetches every few seconds.
    fragment = client.get("/pending-banner").text
    assert "new-fw" in fragment and "<html" not in fragment
    # Its buttons return to the page it is shown on, never to the fragment itself.
    assert 'name="next" value="/pending-banner"' not in fragment
    fragment = client.get("/pending-banner", params={"page": "/devices?org=none"}).text
    assert 'name="next" value="/devices?org=none"' in fragment
    assert 'value="https://evil.example/"' not in client.get("/pending-banner", params={"page": "https://evil.example/"}).text
    r = client.post(f"/devices/{did}/status", data={"action": "nope", "next": "/pending-banner", "csrf_token": csrf})
    assert r.status_code == 400

    r = client.post(f"/devices/{did}/status", data={"action": "approve", "next": "/customers", "csrf_token": csrf},
                    follow_redirects=False)
    assert r.headers["location"] == "/customers"
    db.expire_all()
    assert db.get(Device, did).status == DeviceStatus.offline
    page = client.get("/customers").text
    assert "new-fw approved" in page and "is waiting for approval" not in page
    assert "new-fw" not in client.get("/pending-banner").text


def test_rejecting_deletes_and_redirects_only_inside_the_console(client, db, agent):
    csrf = login(client)
    did = enroll(agent, make_key(db, require_approval=True), system={"hostname": "rogue", "unique_id": "r1"})["device_id"]
    r = client.post(f"/devices/{did}/delete", data={"next": f"/devices/{did}", "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == "/devices"  # not the deleted firewall's page
    assert db.scalar(select(Device).where(Device.id == did)) is None
    other = enroll(agent, make_key(db, require_approval=True), system={"hostname": "b", "unique_id": "b1"})["device_id"]
    r = client.post(f"/devices/{other}/status", data={"action": "approve", "next": "https://evil.example/",
                                                      "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == f"/devices/{other}"
    third = enroll(agent, make_key(db, require_approval=True), system={"hostname": "c", "unique_id": "c1"})["device_id"]
    r = client.post(f"/devices/{third}/status", data={"action": "approve", "next": "/pending-banner?page=/",
                                                      "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == f"/devices/{third}"


def test_only_admins_see_the_banner(client, db, agent):
    enroll(agent, make_key(db, require_approval=True), system={"hostname": "new-fw", "unique_id": "n1"})
    db.add(User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator))
    db.commit()
    login(client, "op", "operator-password-1")
    assert "is waiting for approval" not in client.get("/devices").text
    assert "new-fw" not in client.get("/pending-banner").text
