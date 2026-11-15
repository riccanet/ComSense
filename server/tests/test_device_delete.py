from __future__ import annotations

import base64
import zlib
from urllib.parse import parse_qs, urlsplit

from conftest import csrf_from, enroll, login, make_key
from lxml import etree
from sqlalchemy import select
from test_mfa import _enable_totp
from test_sso import finish, make_response, provider, start  # noqa: F401 - provider is a fixture
from test_terminal import MFA

from app.models import AuditLog, Device, DeviceStatus, Role, User
from app.security import hash_password
from app.services import mfa


def _offline(db, did):
    device = db.get(Device, did)
    device.status = DeviceStatus.offline
    db.commit()
    return device


def test_deleting_a_firewall_needs_its_name_and_an_authenticator_code(client, db, agent):
    did = enroll(agent, make_key(db))["device_id"]
    _offline(db, did)
    csrf = login(client)
    assert f'href="/devices/{did}/delete"' in client.get(f"/devices/{did}").text  # offline: the button
    page = client.get(f"/devices/{did}/delete").text
    assert "Authenticator app required" in page and 'name="code"' not in page
    r = client.post(f"/devices/{did}/delete", data={"csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == f"/devices/{did}/delete"
    db.expire_all()
    assert db.get(Device, did) is not None

    secret, _ = _enable_totp(client, csrf)
    name = db.get(Device, did).name
    code = mfa.totp_code(secret, mfa.current_step() + 1)
    # The wrong name, then the wrong code: nothing is deleted.
    client.post(f"/devices/{did}/delete", data={"confirm_name": "other", "code": code, "csrf_token": csrf})
    client.post(f"/devices/{did}/delete", data={"confirm_name": name, "code": "000000", "csrf_token": csrf})
    db.expire_all()
    assert db.get(Device, did) is not None
    assert db.scalar(select(AuditLog).where(AuditLog.action == "device.delete_denied"))

    r = client.post(f"/devices/{did}/delete", data={"confirm_name": name.upper(), "code": code, "csrf_token": csrf},
                    follow_redirects=False)
    assert r.headers["location"] == "/devices"
    db.expire_all()
    assert db.get(Device, did) is None
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "device.deleted"))
    assert "authenticator code" in entry.detail


def test_only_admins_delete(client, db, agent):
    did = enroll(agent, make_key(db))["device_id"]
    db.add(User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator))
    db.commit()
    csrf = login(client, "op", "operator-password-1")
    assert client.get(f"/devices/{did}/delete").status_code == 403
    assert client.post(f"/devices/{did}/delete", data={"csrf_token": csrf}).status_code == 403


def test_single_sign_on_admins_approve_with_their_provider(client, db, agent, provider):
    did = enroll(agent, make_key(db))["device_id"]
    name = _offline(db, did).name
    db.add(User(username="boss", email="boss@example.com", password_hash=hash_password("x" * 20), role=Role.admin))
    db.commit()
    finish(client, provider.id, make_response(provider.id, start(client, provider.id), "boss@example.com"))
    page = client.get(f"/devices/{did}/delete").text
    assert "Approve with Entra" in page and "Authenticator app required" not in page

    def step_up(confirm=name, as_terminal=False, **response):
        page = client.get(f"/devices/{did}/delete").text
        r = client.post(f"/devices/{did}/delete/sso", data={"confirm_name": confirm, "csrf_token": csrf_from(page)},
                        follow_redirects=False)
        if not r.headers["location"].startswith("https://idp.example.com/sso"):
            return r
        q = parse_qs(urlsplit(r.headers["location"]).query)
        req = etree.fromstring(zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15))
        assert req.get("ForceAuthn") == "true"
        r = client.post(f"/sso/{provider.id}/acs", data={"SAMLResponse": make_response(
            provider.id, req.get("ID"), response.pop("email", "boss@example.com"), **response)}, follow_redirects=False)
        target = r.text.split("url=", 1)[1].split('"', 1)[0]
        assert target.startswith(f"/devices/{did}/delete/sso/")
        if as_terminal:  # a deletion approval cannot open a terminal
            return client.get(target.replace("/delete/", "/terminal/"), follow_redirects=False)
        return client.get(target, follow_redirects=False)

    assert step_up(confirm="nope").headers["location"] == f"/devices/{did}/delete"
    assert step_up().headers["location"] == f"/devices/{did}/delete"  # no MFA claim
    assert step_up(attrs=MFA, email="alice@example.com").headers["location"] == f"/devices/{did}/delete"
    assert step_up(attrs=MFA, as_terminal=True).status_code in (303, 403)
    db.expire_all()
    assert db.get(Device, did) is not None
    r = step_up(attrs=MFA)
    assert r.headers["location"] == "/devices"
    db.expire_all()
    assert db.get(Device, did) is None
    assert "Entra" in db.scalar(select(AuditLog).where(AuditLog.action == "device.deleted")).detail
