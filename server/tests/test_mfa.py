from __future__ import annotations

import base64
import re

import pytest
from sqlalchemy import select
from conftest import ADMIN_PASSWORD, csrf_from, login

from app.models import User
from app.services import mfa
from app.services.appsettings import EmailSettings, save_email_settings


def test_totp_matches_rfc6238_and_codes_work_once():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.totp_code(secret, 59 // 30) == "287082"
    assert mfa.totp_code(secret, 1111111109 // 30) == "081804"
    step = mfa.match_totp(secret, "287082", 0, now=59)
    assert step == 1
    assert mfa.match_totp(secret, "287082", step, now=59) is None  # replay refused
    assert mfa.match_totp(secret, "000000", 0, now=59) is None


def _password_step(client, username="admin", password=ADMIN_PASSWORD):
    token = csrf_from(client.get("/login").text)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token},
                       follow_redirects=False)


def _enable_totp(client, csrf, password=ADMIN_PASSWORD) -> tuple[str, list[str]]:
    client.post("/account/mfa/totp/start", data={"csrf_token": csrf})
    page = client.get("/account").text
    assert '<svg' in page and 'class="qr"' in page
    secret = re.search(r'enter this key by hand: <span class="mono">([A-Z2-7]+)</span>', page).group(1)
    code = mfa.totp_code(secret, mfa.current_step())
    page = client.post("/account/mfa/totp/confirm", data={"code": code, "password": password,
                                                          "csrf_token": csrf}).text
    codes = _recovery_codes(page)
    assert len(codes) == 10
    assert not _recovery_codes(client.get("/account").text)  # shown once
    return secret, codes


def _recovery_codes(page: str) -> list[str]:
    box = re.search(r'<pre class="mono">(.*?)</pre>', page, re.S)
    return re.findall(r"[a-z2-9]{5}-[a-z2-9]{5}", box.group(1)) if box else []


def test_authenticator_app_setup_and_two_step_sign_in(client, db, settings):
    csrf = login(client)
    secret, codes = _enable_totp(client, csrf)
    db.expire_all()
    admin = db.query(User).filter_by(username="admin").one()
    assert admin.totp_enabled and admin.totp_secret and secret not in admin.totp_secret  # stored encrypted

    client.post("/logout", data={"csrf_token": csrf})
    r = _password_step(client)
    assert r.headers["location"] == "/login/mfa"
    # Password alone is not a session.
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    page = client.get("/login/mfa").text
    mfa_csrf = csrf_from(page)
    r = client.post("/login/mfa", data={"code": "000000", "csrf_token": mfa_csrf}, follow_redirects=False)
    assert r.headers["location"] == "/login/mfa"
    # The code used to turn the app on cannot be used again; the next one can.
    next_code = mfa.totp_code(secret, mfa.current_step() + 1)
    r = client.post("/login/mfa", data={"code": next_code, "csrf_token": mfa_csrf}, follow_redirects=False)
    assert r.headers["location"] == "/"
    assert client.get("/", follow_redirects=False).status_code in (200, 303)
    assert client.get("/devices").status_code == 200

    # A recovery code works once.
    client.post("/logout", data={"csrf_token": csrf_from(client.get("/devices").text)})
    _password_step(client)
    mfa_csrf = csrf_from(client.get("/login/mfa").text)
    r = client.post("/login/mfa", data={"code": codes[0].upper(), "csrf_token": mfa_csrf}, follow_redirects=False)
    assert r.headers["location"] == "/"
    db.expire_all()
    assert len(db.query(User).filter_by(username="admin").one().recovery_codes) == 9
    client.post("/logout", data={"csrf_token": csrf_from(client.get("/devices").text)})
    _password_step(client)
    mfa_csrf = csrf_from(client.get("/login/mfa").text)
    r = client.post("/login/mfa", data={"code": codes[0], "csrf_token": mfa_csrf}, follow_redirects=False)
    assert r.headers["location"] == "/login/mfa"


def test_too_many_wrong_codes_start_over(client, db):
    csrf = login(client)
    _enable_totp(client, csrf)
    client.post("/logout", data={"csrf_token": csrf})
    _password_step(client)
    mfa_csrf = csrf_from(client.get("/login/mfa").text)
    for _ in range(4):
        r = client.post("/login/mfa", data={"code": "111111", "csrf_token": mfa_csrf}, follow_redirects=False)
        assert r.headers["location"] == "/login/mfa"
    r = client.post("/login/mfa", data={"code": "111111", "csrf_token": mfa_csrf}, follow_redirects=False)
    assert r.headers["location"] == "/login"
    assert client.get("/login/mfa", follow_redirects=False).headers["location"] == "/login"


@pytest.fixture
def sent_codes(monkeypatch, db, settings):
    save_email_settings(db, EmailSettings(enabled=True, host="smtp.example.com", from_address="cs@example.com"), "t")
    db.commit()
    sent: list[str] = []
    from app.web import mfa_routes

    monkeypatch.setattr(mfa_routes, "_send_code", lambda db, s, user, code, purpose: sent.append(code))
    return sent


def test_email_codes(client, db, sent_codes):
    csrf = login(client)
    client.post("/account/profile", data={"email": "admin@example.com", "password": ADMIN_PASSWORD, "csrf_token": csrf})
    client.post("/account/mfa/email/start", data={"csrf_token": csrf})
    r = client.post("/account/mfa/email/confirm", data={"code": "000000", "csrf_token": csrf})
    db.expire_all()
    assert not db.query(User).filter_by(username="admin").one().mfa_email_enabled
    client.post("/account/mfa/email/confirm", data={"code": sent_codes[-1], "csrf_token": csrf})
    db.expire_all()
    assert db.query(User).filter_by(username="admin").one().mfa_email_enabled

    client.post("/logout", data={"csrf_token": csrf})
    _password_step(client)
    page = client.get("/login/mfa").text  # email is the only method: the code is sent at once
    assert "emailed" in page and len(sent_codes) == 2
    r = client.post("/login/mfa", data={"code": sent_codes[-1], "csrf_token": csrf_from(page)}, follow_redirects=False)
    assert r.headers["location"] == "/"


def test_required_mfa_sends_users_to_setup_first(client, db):
    csrf = login(client)
    r = client.post("/settings/security", data={"mfa_required": "all", "csrf_token": csrf}, follow_redirects=False)
    # At least one method must be allowed when it is required.
    assert "Allow at least one method" in client.get(r.headers["location"]).text
    client.post("/settings/security", data={"mfa_required": "all", "allow_totp": "true", "csrf_token": csrf})
    assert client.get("/devices", follow_redirects=False).headers["location"] == "/account#mfa"
    assert client.get("/account").status_code == 200
    secret, _ = _enable_totp(client, csrf)
    assert client.get("/devices").status_code == 200
    # The only required method cannot be turned off.
    client.post("/account/mfa/totp/disable", data={"password": ADMIN_PASSWORD, "csrf_token": csrf})
    db.expire_all()
    assert db.query(User).filter_by(username="admin").one().totp_enabled


def test_admin_can_reset_a_users_mfa(client, db):
    from app.models import Role
    from app.security import hash_password

    csrf = login(client)
    _enable_totp(client, csrf)
    other = User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator,
                 totp_enabled=True, totp_secret="x", recovery_codes=["a"])
    db.add(other)
    db.commit()
    assert "Reset two-factor sign-in" in client.get(f"/users/{other.id}").text
    client.post(f"/users/{other.id}/mfa-reset", data={"csrf_token": csrf})
    db.expire_all()
    other = db.get(User, other.id)
    assert not other.totp_enabled and not other.totp_secret and not other.recovery_codes


def test_setting_up_an_authenticator_needs_the_password_and_never_replaces_one(client, db):
    csrf = login(client)
    client.post("/account/mfa/totp/start", data={"csrf_token": csrf})
    secret = re.search(r'enter this key by hand: <span class="mono">([A-Z2-7]+)</span>', client.get("/account").text).group(1)
    code = mfa.totp_code(secret, mfa.current_step())
    page = client.post("/account/mfa/totp/confirm", data={"code": code, "password": "wrong", "csrf_token": csrf}).text
    assert "Your password is not correct" in page
    db.expire_all()
    assert not db.scalar(select(User).where(User.username == "admin")).totp_enabled
    _enable_totp(client, csrf)
    page = client.post("/account/mfa/totp/start", data={"csrf_token": csrf}).text
    assert "already set up" in page and "enter this key by hand" not in page


def test_email_codes_in_the_session_cookie_cannot_be_reversed():
    code, record = mfa.new_email_code("k" * 48, "login:1")
    assert "hash" not in record and code not in str(record)
    # A plain SHA-256 of the code would be found by trying a million codes; the MAC needs the server key.
    assert not any(mfa.check_email_code(record, code, "x" * 48, "login:1") for _ in [0])
    assert not mfa.check_email_code(record, code, "k" * 48, "login:2")  # bound to its user and purpose
    assert mfa.check_email_code(record, code, "k" * 48, "login:1")
