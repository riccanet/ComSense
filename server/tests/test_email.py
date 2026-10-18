from __future__ import annotations

import email
import re
import socketserver
import threading
from datetime import timedelta

import pytest
from conftest import ADMIN_PASSWORD, auth, csrf_from, enroll, login, make_key
from sqlalchemy import select

from app.models import Alert, AppSetting, PasswordResetToken, User, utcnow
from app.security import hash_password
from app.services.appsettings import get_alert_email_settings
from app.services.notifications import send_alert_notifications


class _SMTPHandler(socketserver.StreamRequestHandler):
    """Just enough SMTP to accept messages; they are stored on the server."""

    def handle(self):
        self.wfile.write(b"220 test ESMTP\r\n")
        rcpts = []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode().strip()
            upper = cmd.upper()
            if upper.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250-test\r\n250 AUTH PLAIN LOGIN\r\n")
            elif upper.startswith("AUTH"):
                self.server.auth.append(cmd)
                self.wfile.write(b"235 ok\r\n")
            elif upper.startswith("RCPT TO"):
                rcpts.append(re.search(r"<(.*)>", cmd).group(1))
                self.wfile.write(b"250 ok\r\n")
            elif upper == "DATA":
                self.wfile.write(b"354 go\r\n")
                chunks = []
                while True:
                    part = self.rfile.readline()
                    if part in (b".\r\n", b".\n", b""):
                        break
                    chunks.append(part[1:] if part.startswith(b"..") else part)
                data = b"".join(chunks)
                self.server.messages.append((rcpts, email.message_from_bytes(data)))
                rcpts = []
                self.wfile.write(b"250 queued\r\n")
            elif upper == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                return
            else:
                self.wfile.write(b"250 ok\r\n")


class _SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture
def smtp():
    server = _SMTPServer(("127.0.0.1", 0), _SMTPHandler)
    server.messages, server.auth = [], []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _configure_email(client, smtp, csrf, **extra):
    data = {
        "enabled": "true",
        "host": "127.0.0.1",
        "port": str(smtp.server_address[1]),
        "security": "none",
        "username": "mailer",
        "password": "smtp-secret-pw",
        "from_address": "comsense@example.com",
        "from_name": "ComSense",
        "csrf_token": csrf,
        **extra,
    }
    resp = client.post("/settings/email", data=data)
    assert resp.status_code == 200 and "Email settings saved" in resp.text


def _text(msg) -> str:
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            return part.get_payload(decode=True).decode()
    return ""


def test_settings_require_admin(client, db):
    db.add(User(username="op", password_hash=hash_password(ADMIN_PASSWORD), role="operator"))
    db.commit()
    login(client, "op")
    assert client.get("/settings").status_code == 403


def test_email_settings_saved_with_encrypted_password_and_test_email(client, db, smtp):
    csrf = login(client)
    _configure_email(client, smtp, csrf)
    row = db.get(AppSetting, "email")
    assert row.value["host"] == "127.0.0.1"
    assert "smtp-secret-pw" not in str(row.value) and row.value["password_encrypted"]

    # Saving again with a blank password keeps the stored one.
    _configure_email(client, smtp, csrf, password="")
    db.expire_all()
    assert db.get(AppSetting, "email").value["password_encrypted"] == row.value["password_encrypted"]

    resp = client.post("/settings/email/test", data={"to": "me@example.com", "csrf_token": csrf})
    assert "Test email sent" in resp.text
    rcpts, msg = smtp.messages[-1]
    assert rcpts == ["me@example.com"] and msg["Subject"] == "ComSense test email"
    assert smtp.auth, "the saved SMTP credentials are used"


def test_test_email_reports_failure(client, smtp):
    csrf = login(client)
    _configure_email(client, smtp, csrf, port="1")  # nothing listens there
    resp = client.post("/settings/email/test", data={"to": "me@example.com", "csrf_token": csrf})
    assert "Sending failed" in resp.text


def test_password_reset_by_email(client, db, smtp):
    csrf = login(client)
    _configure_email(client, smtp, csrf)
    client.post("/users", data={"username": "alice", "password": "temporary-pass-1", "role": "viewer",
                                "email": "alice@example.com", "csrf_token": csrf})
    client.post("/logout", data={"csrf_token": csrf})

    page = client.get("/login").text
    assert "/forgot" in page
    csrf = csrf_from(client.get("/forgot").text)
    resp = client.post("/forgot", data={"identifier": "Alice@Example.com", "csrf_token": csrf})
    assert "reset link is on its way" in resp.text
    rcpts, msg = smtp.messages[-1]
    assert rcpts == ["alice@example.com"]
    link = re.search(r"https://comsense\.test(/reset/\S+)", _text(msg)).group(1)

    page = client.get(link)
    assert "Set a new password for alice" in page.text
    csrf = csrf_from(page.text)
    done = client.post(link, data={"new": "alice-new-password", "confirm": "alice-new-password", "csrf_token": csrf})
    assert "Password changed" in done.text
    alice = db.scalar(select(User).where(User.username == "alice"))
    db.refresh(alice)
    assert not alice.must_change_password

    # The link works once.
    assert "invalid, already used or expired" in client.get(link).text
    # And the new password signs in straight to the dashboard.
    token = csrf_from(client.get("/login").text)
    resp = client.post("/login", data={"username": "alice", "password": "alice-new-password", "csrf_token": token},
                       follow_redirects=False)
    assert resp.headers["location"] == "/"


def test_forgot_password_does_not_reveal_accounts(client, db, smtp):
    csrf = login(client)
    _configure_email(client, smtp, csrf)
    client.post("/logout", data={"csrf_token": csrf})
    csrf = csrf_from(client.get("/forgot").text)
    for who in ("nobody", "admin"):  # admin exists but has no email address
        resp = client.post("/forgot", data={"identifier": who, "csrf_token": csrf})
        assert "reset link is on its way" in resp.text
    assert smtp.messages == []
    assert db.scalar(select(PasswordResetToken)) is None


def test_expired_reset_link_is_refused(client, db, smtp):
    from app.services.notifications import create_reset_token

    admin = db.scalar(select(User).where(User.username == "admin"))
    token = create_reset_token(db, admin)
    db.commit()
    row = db.scalar(select(PasswordResetToken))
    row.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert "invalid, already used or expired" in client.get(f"/reset/{token}").text


def test_admin_sends_reset_link(client, db, smtp):
    csrf = login(client)
    _configure_email(client, smtp, csrf)
    client.post("/users", data={"username": "bob", "password": "temporary-pass-1", "role": "viewer",
                                "email": "bob@example.com", "csrf_token": csrf})
    bob = db.scalar(select(User).where(User.username == "bob"))
    resp = client.post(f"/users/{bob.id}/send-reset", data={"csrf_token": csrf})
    assert "reset link sent to bob@example.com" in resp.text
    rcpts, msg = smtp.messages[-1]
    assert rcpts == ["bob@example.com"] and "An administrator requested" in _text(msg)


def _alerts_on(client, csrf, **extra):
    data = {"enabled": "true", "min_severity": "warning", "notify_resolved": "true",
            "extra_recipients": "noc@example.com", "csrf_token": csrf, **extra}
    assert "Alert email settings saved" in client.post("/settings/alerts", data=data).text


def test_alert_emails(client, db, agent, smtp, settings):
    csrf = login(client)
    _configure_email(client, smtp, csrf)
    client.post("/account/profile", data={"email": "admin@example.com", "email_alerts": "true", "csrf_token": csrf})
    creds = enroll(agent, make_key(db))
    # An alert that existed before alert email was switched on is never sent.
    agent.post("/api/agent/v1/checkin", json={"gateways": [{"name": "OLD", "status": "down"}]}, headers=auth(creds["token"]))
    _alerts_on(client, csrf)
    db.expire_all()
    cfg = get_alert_email_settings(db)
    old = db.scalar(select(Alert).where(Alert.key == "gateway:OLD"))
    old.opened_at = utcnow() - timedelta(minutes=5)
    db.commit()
    assert cfg.enabled_since

    report = {"gateways": [{"name": "OLD", "status": "down"}, {"name": "WAN", "status": "down"}],
              "metrics": {"disk_pct": 95}}
    agent.post("/api/agent/v1/checkin", json=report, headers=auth(creds["token"]))
    sent = send_alert_notifications(db, settings)
    db.commit()
    assert sent == 2
    recipients = sorted(r[0] for r, _ in smtp.messages)
    assert recipients == ["admin@example.com", "noc@example.com"]
    msg = smtp.messages[0][1]
    assert "CRITICAL" in msg["Subject"] and "2 new alerts" in msg["Subject"]
    text = _text(msg)
    assert "Gateway WAN is down" in text and "Disk usage is 95%" in text and "OLD" not in text

    # Nothing new: nothing sent.
    assert send_alert_notifications(db, settings) == 0
    # When they clear, one "resolved" summary goes out.
    agent.post("/api/agent/v1/checkin", json={"gateways": [{"name": "OLD", "status": "online"}, {"name": "WAN", "status": "online"}]},
               headers=auth(creds["token"]))
    smtp.messages.clear()
    assert send_alert_notifications(db, settings) == 2
    db.commit()
    assert "2 resolved" in smtp.messages[0][1]["Subject"]
    assert send_alert_notifications(db, settings) == 0


def test_alert_emails_respect_severity_and_retry_on_failure(client, db, agent, smtp, settings):
    csrf = login(client)
    _configure_email(client, smtp, csrf)
    _alerts_on(client, csrf, min_severity="critical", notify_resolved="")
    creds = enroll(agent, make_key(db))
    agent.post("/api/agent/v1/checkin", json={"metrics": {"disk_pct": 99}}, headers=auth(creds["token"]))
    assert send_alert_notifications(db, settings) == 0  # warning only: skipped
    db.commit()

    # Mail server down: the critical alert stays pending and goes out once it is back.
    smtp_port = smtp.server_address[1]
    _configure_email(client, smtp, csrf, port="1")
    agent.post("/api/agent/v1/checkin", json={"metrics": {"disk_pct": 99}, "gateways": [{"name": "WAN", "status": "down"}]},
               headers=auth(creds["token"]))
    db.expire_all()
    assert send_alert_notifications(db, settings) == 0
    db.commit()
    assert db.scalar(select(Alert).where(Alert.key == "gateway:WAN")).notified_at is None
    _configure_email(client, smtp, csrf, port=str(smtp_port))
    db.expire_all()
    assert send_alert_notifications(db, settings) == 1
    assert "Gateway WAN is down" in _text(smtp.messages[-1][1])


def test_profile_email_and_alert_opt_in(client, db):
    csrf = login(client)
    assert "not a valid email" in client.post("/account/profile", data={"email": "nope", "csrf_token": csrf}).text
    client.post("/account/profile", data={"email": "me@example.com", "email_alerts": "true", "csrf_token": csrf})
    admin = db.scalar(select(User).where(User.username == "admin"))
    db.refresh(admin)
    assert admin.email == "me@example.com" and admin.email_alerts
