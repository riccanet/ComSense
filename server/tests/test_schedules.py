"""Bulk updates from the Firewalls page, and scheduled jobs (Schedules) run by the scheduler."""
from __future__ import annotations

import html
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from conftest import auth, enroll, login, make_key
from sqlalchemy import select

from app.models import JobStatus, ScheduledJob, Task, TaskType, aware, utcnow
from app.scheduler import run_once
from app.services import appsettings
from app.services.schedules import local_input, next_run, run_due_jobs

UPGRADE = {"update_available": True, "version": "26.07", "installed_version": "26.03.1",
           "packages": [{"name": "pfSense-pkg-Nexus", "installed": "26.03.1", "available": "26.07_3"}]}
CURRENT = {"update_available": False, "version": "26.03.1", "installed_version": "26.03.1", "packages": []}


def _firewall(agent, db, name, updates=None, capabilities=None):
    creds = enroll(agent, make_key(db), capabilities=capabilities,
                   system={"hostname": name, "edition": "plus", "version": "26.03.1-RELEASE", "unique_id": name})
    if updates is not None:
        agent.post("/api/agent/v1/checkin", json={"updates": updates}, headers=auth(creds["token"]))
    return creds["device_id"]


def _tasks(db, ttype):
    db.expire_all()
    return db.scalars(select(Task).where(Task.type == ttype).order_by(Task.id)).all()


@pytest.mark.changes
def test_bulk_upgrade_only_where_an_update_is_available(client, db, agent):
    csrf = login(client)
    behind = _firewall(agent, db, "fw-behind", UPGRADE)
    current = _firewall(agent, db, "fw-current", CURRENT)
    silent = _firewall(agent, db, "fw-silent")
    locked = _firewall(agent, db, "fw-locked", UPGRADE, capabilities=["backup"])
    page = client.get("/devices").text
    assert "Upgrade pfSense (reboots; where an update is available)" in page and "Schedule…" in page

    r = client.post("/devices/bulk", data={"csrf_token": csrf, "task_type": "upgrade_system",
                                           "device_ids": [behind, current, silent, locked]})
    text = html.unescape(r.text)
    assert "queued on 1 firewall(s); 1 already up to date; 1 have not reported their update status; 1 refused (fw-locked:" in text
    assert [t.device_id for t in _tasks(db, TaskType.upgrade_system)] == [behind]
    # The configuration is backed up first, as for a single upgrade.
    assert any(t.payload.get("reason") for t in _tasks(db, TaskType.backup) if t.device_id == behind)

    # Run again: it is already running there, so nothing is queued twice.
    r = client.post("/devices/bulk", data={"csrf_token": csrf, "task_type": "upgrade_system", "device_ids": [behind]})
    assert "1 already running it" in html.unescape(r.text)
    assert len(_tasks(db, TaskType.upgrade_system)) == 1

    client.post("/devices/bulk", data={"csrf_token": csrf, "task_type": "upgrade_packages",
                                       "device_ids": [behind, current]})
    assert [t.device_id for t in _tasks(db, TaskType.upgrade_packages)] == []  # behind is busy upgrading pfSense


def test_upgrades_are_not_offered_with_firewall_changes_off(client, db, agent):
    csrf = login(client)
    behind = _firewall(agent, db, "fw-behind", UPGRADE)
    assert "Upgrade pfSense" not in client.get("/devices").text
    r = client.post("/devices/bulk", data={"csrf_token": csrf, "task_type": "upgrade_system", "device_ids": [behind]})
    assert "Firewall changes are turned off" in r.text
    assert _tasks(db, TaskType.upgrade_system) == []


@pytest.mark.changes
def test_schedule_from_the_firewalls_page_and_run_it(client, db, agent, settings):
    csrf = login(client)
    behind = _firewall(agent, db, "fw-behind", UPGRADE)
    current = _firewall(agent, db, "fw-current", CURRENT)

    # Schedule… carries the selection and the task over to the form.
    form = client.post("/schedules/new", data={"csrf_token": csrf, "task_type": "upgrade_packages",
                                               "device_ids": [behind]}).text
    assert f'value="{behind}" checked' in form and f'value="{current}" checked' not in form
    assert '<option value="upgrade_packages" selected>' in form

    start = utcnow() + timedelta(hours=1)
    r = client.post("/schedules", data={"csrf_token": csrf, "action": "upgrade_packages", "device_ids": [behind, current],
                                        "run_at": local_input(start), "repeat": "weekly", "window": "120",
                                        "name": "Weekly packages"})
    assert r.status_code == 200 and "Scheduled: Upgrade packages" in html.unescape(r.text)
    job = db.scalar(select(ScheduledJob))
    assert job.device_ids == [behind, current] and job.repeat == "weekly" and job.window_minutes == 120
    assert "Weekly packages" in client.get("/schedules").text

    # Not due yet.
    run_once(settings)
    assert _tasks(db, TaskType.upgrade_packages) == []

    # Due: queued where there is something to upgrade, valid for the window; the next run is a week on.
    at = aware(job.run_at) + timedelta(minutes=1)
    assert run_due_jobs(db, settings, at) == 1
    db.commit()
    tasks = _tasks(db, TaskType.upgrade_packages)
    assert [t.device_id for t in tasks] == [behind]
    assert aware(tasks[0].not_after) - utcnow() < timedelta(minutes=121)
    db.refresh(job)
    assert job.status == JobStatus.scheduled and aware(job.run_at) - at > timedelta(days=6)
    assert "queued on 1 firewall(s); 1 already up to date" in job.last_result["summary"]
    assert job.last_result["queued"] == ["fw-behind"]

    # Cancel stops it; a cancelled job can then be removed.
    client.post(f"/schedules/{job.id}/cancel", data={"csrf_token": csrf})
    db.refresh(job)
    assert job.status == JobStatus.cancelled
    assert run_due_jobs(db, settings, aware(job.run_at) + timedelta(minutes=1)) == 0
    client.post(f"/schedules/{job.id}/delete", data={"csrf_token": csrf})
    db.expire_all()
    assert db.scalar(select(ScheduledJob)) is None


def test_one_off_job_on_all_firewalls_and_a_missed_one(client, db, agent, settings):
    csrf = login(client)
    first = _firewall(agent, db, "fw-a")
    start = utcnow() + timedelta(minutes=30)
    client.post("/schedules", data={"csrf_token": csrf, "action": "backup", "all_devices": "1",
                                    "run_at": local_input(start), "repeat": "", "window": "60"})
    job = db.scalar(select(ScheduledJob))
    assert job.device_ids is None
    later = _firewall(agent, db, "fw-b")  # added after the job was scheduled: included too

    run_due_jobs(db, settings, aware(job.run_at) + timedelta(seconds=30))
    db.commit()
    db.refresh(job)
    assert job.status == JobStatus.done
    assert {t.device_id for t in _tasks(db, TaskType.backup)} >= {first, later}
    page = client.get("/schedules").text
    assert "Finished and cancelled" in page and "All firewalls" in page and "fw-a, fw-b" in page

    # A job whose time passed while the server was down, beyond its window, is not run late.
    missed = ScheduledJob(name="old", action="backup", device_ids=None, run_at=utcnow() - timedelta(hours=3),
                          window_minutes=60)
    db.add(missed)
    db.commit()
    before = len(_tasks(db, TaskType.backup))
    assert run_due_jobs(db, settings) == 0
    db.commit()
    assert len(_tasks(db, TaskType.backup)) == before
    db.refresh(missed)
    assert missed.status == JobStatus.done and missed.last_result["summary"].startswith("Missed")


def test_form_validation_and_run_now(client, db, agent, settings):
    csrf = login(client)
    fw = _firewall(agent, db, "fw-a")
    base = {"csrf_token": csrf, "action": "check_updates", "device_ids": [fw], "repeat": "daily", "window": "240"}
    r = client.post("/schedules", data={**base, "run_at": local_input(utcnow() - timedelta(hours=2))})
    assert r.status_code == 400 and "in the past" in r.text
    r = client.post("/schedules", data={**base, "device_ids": [], "run_at": local_input(utcnow() + timedelta(hours=2))})
    assert r.status_code == 400 and "Choose the firewalls" in r.text
    r = client.post("/schedules", data={**base, "action": "upgrade_system",
                                        "run_at": local_input(utcnow() + timedelta(hours=2))})
    assert r.status_code == 400  # firewall changes are off in this test
    client.post("/schedules", data={**base, "run_at": local_input(utcnow() + timedelta(hours=2))})
    job = db.scalar(select(ScheduledJob))
    run_at = job.run_at

    # Run now queues it at once and leaves the schedule as it was.
    r = client.post(f"/schedules/{job.id}/run", data={"csrf_token": csrf})
    assert "Check for updates: queued on 1 firewall(s)" in html.unescape(r.text)
    assert len(_tasks(db, TaskType.check_updates)) == 1
    db.refresh(job)
    assert job.status == JobStatus.scheduled and aware(job.run_at) == aware(run_at)
    assert client.get(f"/schedules/{job.id}").status_code == 200


def test_times_are_in_the_console_time_zone_across_daylight_saving():
    ny = ZoneInfo("America/New_York")
    appsettings._tz_cache.update(at=float("inf"), tz=ny)
    # 2:00 AM Saturday Oct 31 2026 in New York (EDT); daylight saving ends Sunday Nov 1.
    start = datetime(2026, 10, 31, 2, 0, tzinfo=ny)
    nxt = next_run(start, "daily", start.astimezone(timezone.utc))
    assert nxt.astimezone(ny).hour == 2 and nxt.astimezone(ny).day == 1
    assert nxt.astimezone(timezone.utc) - start.astimezone(timezone.utc) == timedelta(hours=25)  # still 2:00 AM
    assert local_input(start) == "2026-10-31T02:00"
