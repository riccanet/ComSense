"""Settings > Alert categories: which alerts are raised and emailed, thresholds, and daily reminders."""
from __future__ import annotations

from datetime import timedelta

from conftest import auth, enroll, login, make_key
from sqlalchemy import select
from test_email import _alerts_on, _configure_email, _text, smtp  # noqa: F401 - smtp is a fixture

from app.models import Alert, Device, utcnow
from app.services import alerts as alert_svc
from app.services.appsettings import get_alert_category_settings
from app.services.notifications import send_alert_notifications

ALL_ON = {f"{c}_{f}": "true" for c in alert_svc.CATEGORIES for f in ("enabled", "email", "repeat")}
THRESHOLDS = {"repeat_hours": "24", "disk_pct": "90", "memory_pct": "90", "cpu_pct": "90", "states_pct": "90"}


def _save(client, csrf, **changes):
    data = {**ALL_ON, **THRESHOLDS, "csrf_token": csrf}
    for k, v in changes.items():
        if v is None:
            data.pop(k, None)
        else:
            data[k] = v
    r = client.post("/settings/alert-categories", data=data)
    assert r.status_code == 200 and "Alert categories saved" in r.text
    return r


def _open(db) -> dict[str, Alert]:
    db.expire_all()
    return {a.key: a for a in db.scalars(select(Alert).where(Alert.resolved_at.is_(None)))}


def test_page_lists_the_categories_and_saves(client, db):
    csrf = login(client)
    page = client.get("/settings/alert-categories").text
    for name in ("System alerts", "WAN connectivity", "Firewall down", "Services not running", "High resources"):
        assert name in page
    _save(client, csrf, services_enabled=None, wan_repeat=None, repeat_hours="12", disk_pct="80")
    cfg = get_alert_category_settings(db)
    assert not cfg.flag("services", "enabled") and cfg.flag("services", "email")
    assert not cfg.flag("wan", "repeat") and cfg.repeat_hours == 12 and cfg.disk_pct == 80
    assert client.post("/settings/alert-categories", data={**ALL_ON, **THRESHOLDS, "cpu_pct": "150",
                                                           "csrf_token": csrf}).status_code == 400


def test_disabled_categories_and_thresholds(client, db, agent):
    csrf = login(client)
    creds = enroll(agent, make_key(db))
    report = {"services": [{"name": "unbound", "running": False}], "gateways": [{"name": "WAN", "status": "down"}],
              "metrics": {"disk_pct": 85, "states": 950, "states_max": 1000}}
    agent.post("/api/agent/v1/checkin", json=report, headers=auth(creds["token"]))
    assert set(_open(db)) == {"service:unbound", "gateway:WAN", "states"}  # disk 85% is under 90%

    # Services off: its alert clears and is not raised again; a lower disk threshold raises disk.
    _save(client, csrf, services_enabled=None, disk_pct="80")
    agent.post("/api/agent/v1/checkin", json=report, headers=auth(creds["token"]))
    assert set(_open(db)) == {"gateway:WAN", "states", "disk"}

    # Firewall down off: no offline alert.
    _save(client, csrf, down_enabled=None)
    device = db.get(Device, creds["device_id"])
    alert_svc.raise_offline(db, device)
    db.commit()
    assert "offline" not in _open(db)


def test_cpu_alerts_only_when_it_stays_high(client, db, agent):
    login(client)
    creds = enroll(agent, make_key(db))
    for cpu in (95, 97, 40, 96, 99, 98, 95):
        agent.post("/api/agent/v1/checkin", json={"metrics": {"cpu_pct": cpu}}, headers=auth(creds["token"]))
        assert "cpu" not in _open(db)  # never five high check-ins in a row yet
    agent.post("/api/agent/v1/checkin", json={"metrics": {"cpu_pct": 93}}, headers=auth(creds["token"]))
    assert "cpu" in _open(db)
    agent.post("/api/agent/v1/checkin", json={"metrics": {"cpu_pct": 20}}, headers=auth(creds["token"]))
    assert "cpu" not in _open(db)


def test_rollbacks_with_system_alerts_off_are_recorded_resolved(client, db, agent):
    csrf = login(client)
    _save(client, csrf, system_enabled=None)
    creds = enroll(agent, make_key(db))
    event = {"id": "rb1", "tasks": [], "changes": "rule", "reason": "lost contact"}
    agent.post("/api/agent/v1/checkin", json={"rollbacks": [event]}, headers=auth(creds["token"]))
    db.expire_all()
    alert = db.scalar(select(Alert).where(Alert.key == "rollback:rb1"))
    assert alert is not None and alert.resolved_at is not None


def test_unacknowledged_alerts_are_emailed_again_every_day(client, db, agent, smtp, settings):
    csrf = login(client)
    _configure_email(client, smtp, csrf)
    _alerts_on(client, csrf)
    creds = enroll(agent, make_key(db))
    report = {"gateways": [{"name": "WAN", "status": "down"}, {"name": "LTE", "status": "down"}],
              "services": [{"name": "unbound", "running": False}]}
    agent.post("/api/agent/v1/checkin", json=report, headers=auth(creds["token"]))
    assert send_alert_notifications(db, settings) == 1
    db.commit()
    assert "3 new alerts" in smtp.messages[-1][1]["Subject"]

    # Not due yet: nothing.
    assert send_alert_notifications(db, settings) == 0
    # A day later, the two that nobody acknowledged go out again; the acknowledged one does not.
    alerts = _open(db)
    for a in alerts.values():
        a.notified_at = utcnow() - timedelta(hours=25)
    alerts["gateway:LTE"].acknowledged_by = "admin"
    db.commit()
    smtp.messages.clear()
    assert send_alert_notifications(db, settings) == 1
    db.commit()
    msg = smtp.messages[-1][1]
    assert "2 still open" in msg["Subject"] and "CRITICAL" in msg["Subject"]
    text = _text(msg)
    assert "Gateway WAN is down" in text and "Service unbound is not running" in text and "LTE" not in text
    assert send_alert_notifications(db, settings) == 0  # the next reminder is a day away again

    # Services stop repeating; WAN email off: neither is repeated, and new WAN alerts are not emailed.
    _save(client, csrf, services_repeat=None, wan_email=None)
    for a in _open(db).values():
        a.notified_at = utcnow() - timedelta(hours=25)
    db.commit()
    agent.post("/api/agent/v1/checkin", json={**report, "gateways": report["gateways"] + [{"name": "WAN2", "status": "down"}]},
               headers=auth(creds["token"]))
    assert send_alert_notifications(db, settings) == 0


def test_alerts_page_shows_and_filters_categories(client, db, agent):
    login(client)
    creds = enroll(agent, make_key(db))
    agent.post("/api/agent/v1/checkin", json={"gateways": [{"name": "WAN", "status": "down"}],
                                              "services": [{"name": "unbound", "running": False}]},
               headers=auth(creds["token"]))
    page = client.get("/alerts").text
    assert "WAN connectivity" in page and "Services not running" in page
    wan = client.get("/alerts?category=wan").text
    assert "Gateway WAN is down" in wan and "unbound is not running" not in wan
    assert "Gateway WAN is down" not in client.get("/alerts?category=services").text
