from __future__ import annotations

import json
from datetime import timedelta

import pytest
from conftest import ALL_CAPS, SYSTEM, auth, csrf_from, enroll, login, make_key
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect
from test_mfa import _enable_totp

from app.models import AuditLog, Role, Task, TaskType, TerminalSession, TerminalStatus, User, utcnow
from app.security import hash_password
from app.services import mfa
from app.services import terminal as terminal_svc

ORIGIN = {"origin": "http://testserver"}


def _approve(client, device_id, secret, step_offset=1):
    page = client.get(f"/devices/{device_id}/terminal").text
    code = mfa.totp_code(secret, mfa.current_step() + step_offset)
    return client.post(f"/devices/{device_id}/terminal", data={"code": code, "csrf_token": csrf_from(page)},
                       follow_redirects=False)


@pytest.fixture
def shell_device(agent, db):
    return enroll(agent, make_key(db), capabilities=[*ALL_CAPS, "shell"])


def test_terminal_needs_an_authenticator_app_and_the_firewall_permission(client, db, agent, shell_device):
    csrf = login(client)
    did = shell_device["device_id"]
    page = client.get(f"/devices/{did}").text
    assert f'href="/devices/{did}/terminal"' in page
    page = client.get(f"/devices/{did}/terminal").text
    assert "Authenticator app required" in page and 'name="code"' not in page
    r = client.post(f"/devices/{did}/terminal", data={"code": "123456", "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == f"/devices/{did}/terminal"
    assert not db.scalars(select(TerminalSession)).all()

    secret, _ = _enable_totp(client, csrf)
    assert 'name="code"' in client.get(f"/devices/{did}/terminal").text

    # Without the firewall's "Remote terminal" permission there is nothing to approve.
    other = enroll(agent, make_key(db), system={**SYSTEM, "unique_id": "noshell"})
    assert "Not allowed on this firewall" in client.get(f"/devices/{other['device_id']}/terminal").text

    # A wrong code is refused and audited.
    r = client.post(f"/devices/{did}/terminal", data={"code": "000000", "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == f"/devices/{did}/terminal"
    db.expire_all()
    assert db.scalar(select(AuditLog).where(AuditLog.action == "terminal.denied"))
    assert not db.scalars(select(TerminalSession)).all()


def test_terminal_is_admin_only(client, db, shell_device):
    db.add(User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator))
    db.commit()
    login(client, "op", "operator-password-1")
    page = client.get(f"/devices/{shell_device['device_id']}").text
    assert "/terminal" not in page
    assert client.get(f"/devices/{shell_device['device_id']}/terminal").status_code == 403


def test_terminal_session_end_to_end(client, db, agent, shell_device, settings, monkeypatch):
    monkeypatch.setattr(terminal_svc, "WATCH_INTERVAL", 0.05)
    csrf = login(client)
    secret, _ = _enable_totp(client, csrf)
    did = shell_device["device_id"]
    r = _approve(client, did, secret)
    sid = r.headers["location"].removeprefix("/terminal/")
    db.expire_all()
    ts = db.get(TerminalSession, sid)
    assert ts.status == TerminalStatus.approved and ts.username == "admin"
    task = db.scalar(select(Task).where(Task.type == TaskType.open_terminal))
    assert task.payload == {"session": sid} and task.device_id == did
    assert db.scalar(select(AuditLog).where(AuditLog.action == "terminal.approve"))
    # The approval code cannot be used again.
    r = _approve(client, did, secret)
    assert r.headers["location"] == f"/devices/{did}/terminal"

    page = client.get(f"/terminal/{sid}")
    assert 'data-live="1"' in page.text
    assert "style-src 'self' 'unsafe-inline'" in page.headers["content-security-policy"]
    assert "script-src 'self';" in page.headers["content-security-policy"]

    # Only our own pages may open the socket, and only this firewall may join as the other end.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/terminal/{sid}/ws", headers={"origin": "https://evil.example"}):
            pass
    other = enroll(agent, make_key(db), system={**SYSTEM, "unique_id": "other"}, capabilities=[*ALL_CAPS, "shell"])
    with pytest.raises(WebSocketDisconnect):
        with agent.websocket_connect(f"/api/agent/v1/terminal/{sid}", headers=auth(other["token"])):
            pass

    with client.websocket_connect(f"/terminal/{sid}/ws", headers=ORIGIN) as browser:
        assert browser.receive_json()["s"] == "waiting"
        browser.send_text(json.dumps({"t": "r", "c": 120, "r": 40}))
        # A second browser cannot join the same session.
        with client.websocket_connect(f"/terminal/{sid}/ws", headers=ORIGIN) as second:
            assert second.receive_json()["s"] == "closed"
        with agent.websocket_connect(f"/api/agent/v1/terminal/{sid}", headers=auth(shell_device["token"])) as fw:
            assert fw.receive_json() == {"t": "r", "c": 120, "r": 40}
            assert browser.receive_json()["s"] == "connected"
            browser.send_text(json.dumps({"t": "i", "d": "uname -a\r"}))
            assert fw.receive_json() == {"t": "i", "d": "uname -a\r"}
            browser.send_text(json.dumps({"t": "r", "c": 9999, "r": 1}))
            assert fw.receive_json() == {"t": "r", "c": 500, "r": 5}  # clamped
            fw.send_bytes("FreeBSD fw1 é\r\n".encode())
            assert browser.receive_bytes() == "FreeBSD fw1 é\r\n".encode()
            fw.send_text(json.dumps({"t": "x", "m": "The shell exited."}))
            closed = browser.receive_json()
            assert closed == {"t": "s", "s": "closed", "m": "The shell exited."}

    db.expire_all()
    ts = db.get(TerminalSession, sid)
    assert ts.status == TerminalStatus.closed and ts.close_reason == "The shell exited."
    assert ts.connected_at and ts.closed_at and ts.bytes_in == len("uname -a\r") and ts.bytes_out > 0
    actions = [a.action for a in db.scalars(select(AuditLog).where(AuditLog.action.like("terminal.%")))]
    assert {"terminal.approve", "terminal.connect", "terminal.close"} <= set(actions)

    # Recorded as asciicast v2 and replayable; the session cannot be joined again.
    lines = (terminal_svc.recording_dir(settings.data_dir) / ts.recording).read_text().splitlines()
    head = json.loads(lines[0])
    assert head["version"] == 2 and (head["width"], head["height"]) == (120, 40)
    events = [json.loads(line) for line in lines[1:]]
    assert ["r", "500x5"] in [e[1:] for e in events]
    assert "".join(e[2] for e in events if e[1] == "o") == "FreeBSD fw1 é\r\n"
    page = client.get(f"/terminal/{sid}").text
    assert 'data-live="0"' in page and "The shell exited." in page
    rec = client.get(f"/terminal/{sid}/recording?download=1")
    assert rec.status_code == 200 and "attachment" in rec.headers["content-disposition"]
    assert "Replay" in client.get(f"/devices/{did}").text
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/terminal/{sid}/ws", headers=ORIGIN):
            pass


def test_unjoined_sessions_expire(client, db, agent, shell_device, monkeypatch):
    csrf = login(client)
    secret, _ = _enable_totp(client, csrf)
    sid = _approve(client, shell_device["device_id"], secret).headers["location"].removeprefix("/terminal/")
    ts = db.get(TerminalSession, sid)
    ts.created_at = utcnow() - timedelta(seconds=terminal_svc.START_WINDOW + 5)
    db.commit()
    assert 'data-live="1"' not in client.get(f"/terminal/{sid}").text
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/terminal/{sid}/ws", headers=ORIGIN):
            pass
    with pytest.raises(WebSocketDisconnect):
        with agent.websocket_connect(f"/api/agent/v1/terminal/{sid}", headers=auth(shell_device["token"])):
            pass


def test_firewall_that_never_connects_closes_the_session(client, db, shell_device, monkeypatch):
    monkeypatch.setattr(terminal_svc, "WATCH_INTERVAL", 0.05)
    csrf = login(client)
    secret, _ = _enable_totp(client, csrf)
    sid = _approve(client, shell_device["device_id"], secret).headers["location"].removeprefix("/terminal/")
    with client.websocket_connect(f"/terminal/{sid}/ws", headers=ORIGIN) as browser:
        assert browser.receive_json()["s"] == "waiting"
        monkeypatch.setattr(terminal_svc, "START_WINDOW", 0)
        msg = browser.receive_json()
        assert msg["s"] == "closed" and "did not connect" in msg["m"]
    db.expire_all()
    assert db.get(TerminalSession, sid).status == TerminalStatus.closed
