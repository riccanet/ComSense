from __future__ import annotations

import re

from conftest import auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Alert, Device, EnrollmentKey, Organization
from app.services.notifications import _alert_digest


def _add(client, csrf, name, **extra):
    return client.post("/customers", data={"name": name, "csrf_token": csrf, **extra}, follow_redirects=False)


def test_create_customer_with_contact_and_view_it(client, db):
    csrf = login(client)
    resp = _add(client, csrf, "Acme Corp", contact_name="Jane Roe", contact_email="jane@acme.example",
                contact_phone="+1 555 0100", notes="Two sites")
    assert resp.status_code == 303
    acme = db.scalar(select(Organization))
    assert resp.headers["location"] == f"/customers/{acme.id}"
    assert (acme.contact_name, acme.contact_email, acme.contact_phone) == ("Jane Roe", "jane@acme.example", "+1 555 0100")
    page = client.get(f"/customers/{acme.id}").text
    assert "Acme Corp" in page and "No firewalls yet" in page and f"/keys?customer={acme.id}" in page

    assert "already exists" in client.post("/customers", data={"name": "Acme Corp", "csrf_token": csrf}).text
    assert "not a valid address" in client.post(
        "/customers", data={"name": "Beta", "contact_email": "nope", "csrf_token": csrf}).text


def test_firewalls_enrolled_with_a_customer_key_belong_to_it(client, db, agent):
    csrf = login(client)
    _add(client, csrf, "Acme Corp")
    _add(client, csrf, "Globex")
    acme, globex = db.scalars(select(Organization).order_by(Organization.name)).all()
    key = make_key(db, organization_id=acme.id)
    enroll(agent, key, system={"hostname": "acme-hq", "unique_id": "a1"})
    two = enroll(agent, key, system={"hostname": "acme-branch", "unique_id": "a2"})
    enroll(agent, make_key(db, organization_id=globex.id), system={"hostname": "globex-fw", "unique_id": "g1"})
    agent.post("/api/agent/v1/checkin", json={"gateways": [{"name": "WAN", "status": "down"}]}, headers=auth(two["token"]))

    page = client.get(f"/customers/{acme.id}").text
    assert "acme-hq" in page and "acme-branch" in page and "globex-fw" not in page
    assert "Gateway WAN is down" in page

    listing = client.get("/customers").text
    row = re.search(r"Acme Corp</a>.*?</tr>", listing, re.S).group(0)
    assert re.findall(r"<td>(\d+)</td>", row)[0] == "2"

    filtered = client.get(f"/devices?org={acme.id}").text
    assert "acme-hq" in filtered and "globex-fw" not in filtered
    assert {d.organization_id for d in db.scalars(select(Device))} == {acme.id, globex.id}


def test_unassigned_filter_and_moving_a_firewall(client, db, agent):
    csrf = login(client)
    _add(client, csrf, "Acme Corp")
    acme = db.scalar(select(Organization))
    creds = enroll(agent, make_key(db), system={"hostname": "loose-fw", "unique_id": "x1"})
    assert "1 firewall not assigned" in client.get("/customers").text
    assert "loose-fw" in client.get("/devices?org=none").text
    client.post(f"/devices/{creds['device_id']}/edit",
                data={"name": "loose-fw", "organization_id": str(acme.id), "notes": "", "csrf_token": csrf})
    assert "loose-fw" in client.get(f"/customers/{acme.id}").text
    assert "loose-fw" not in client.get("/devices?org=none").text


def test_adding_and_removing_firewalls_on_the_customer_page(client, db, agent):
    csrf = login(client)
    _add(client, csrf, "Acme Corp")
    _add(client, csrf, "Globex")
    acme, globex = db.scalars(select(Organization).order_by(Organization.name)).all()
    one = enroll(agent, make_key(db), system={"hostname": "loose-1", "unique_id": "l1"})["device_id"]
    two = enroll(agent, make_key(db), system={"hostname": "loose-2", "unique_id": "l2"})["device_id"]
    taken = enroll(agent, make_key(db, organization_id=globex.id), system={"hostname": "globex-fw", "unique_id": "g1"})
    page = client.get(f"/customers/{acme.id}").text
    assert "Add firewalls without a customer (2)" in page
    assert f'value="{one}"' in page and f'value="{taken["device_id"]}"' not in page

    client.post(f"/customers/{acme.id}/devices", data={"device_ids": [one, two, taken["device_id"]], "csrf_token": csrf})
    db.expire_all()
    assert db.get(Device, one).organization_id == acme.id and db.get(Device, two).organization_id == acme.id
    assert db.get(Device, taken["device_id"]).organization_id == globex.id  # only unassigned ones are taken
    assert "Add firewalls without a customer" not in client.get(f"/customers/{acme.id}").text

    client.post(f"/customers/{acme.id}/devices/remove", data={"device_id": two, "csrf_token": csrf})
    db.expire_all()
    assert db.get(Device, two).organization_id is None
    assert client.post(f"/customers/{acme.id}/devices/remove",
                       data={"device_id": taken["device_id"], "csrf_token": csrf}).status_code == 404


def test_update_and_delete_customer(client, db, agent):
    csrf = login(client)
    _add(client, csrf, "Acme Corp")
    acme = db.scalar(select(Organization))
    client.post(f"/customers/{acme.id}", data={"name": "Acme Inc", "contact_name": "Bob", "csrf_token": csrf})
    db.refresh(acme)
    assert acme.name == "Acme Inc" and acme.contact_name == "Bob"

    key = make_key(db, organization_id=acme.id)
    creds = enroll(agent, key)
    resp = client.post(f"/customers/{acme.id}/delete", data={"csrf_token": csrf})
    assert "Move its firewalls" in resp.text
    client.post(f"/devices/{creds['device_id']}/delete", data={"csrf_token": csrf})
    client.post(f"/customers/{acme.id}/delete", data={"csrf_token": csrf})
    db.expire_all()
    assert db.scalar(select(Organization)) is None
    assert db.scalar(select(EnrollmentKey)).revoked


def test_old_url_redirects_and_keys_page_preselects(client, db):
    csrf = login(client)
    _add(client, csrf, "Acme Corp")
    acme = db.scalar(select(Organization))
    resp = client.get("/organizations", follow_redirects=False)
    assert resp.status_code == 301 and resp.headers["location"] == "/customers"
    keys = client.get(f"/keys?customer={acme.id}").text
    assert f'<option value="{acme.id}" selected>Acme Corp</option>' in keys


def test_alert_emails_name_the_customer(client, db, agent, settings):
    csrf = login(client)
    _add(client, csrf, "Acme Corp")
    acme = db.scalar(select(Organization))
    creds = enroll(agent, make_key(db, organization_id=acme.id), system={"hostname": "acme-hq", "unique_id": "a1"})
    agent.post("/api/agent/v1/checkin", json={"gateways": [{"name": "WAN", "status": "down"}]}, headers=auth(creds["token"]))
    alert = db.scalar(select(Alert))
    subject, text, html = _alert_digest(settings, [alert], [])
    assert "Acme Corp / acme-hq: Gateway WAN is down" in text
    assert "Acme Corp / acme-hq" in html
