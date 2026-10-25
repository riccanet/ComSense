"""Scheduled jobs: bulk actions (services/bulk.py) run by the scheduler at a set time, once or repeating."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings
from ..models import JobStatus, ScheduledJob, aware, utcnow
from .appsettings import display_timezone, format_dt
from .bulk import BULK_ACTIONS, run_bulk, target_devices
from .tasks import TaskError

log = logging.getLogger("comsense.schedules")

REPEATS = {"": "Once", "daily": "Every day", "weekly": "Every week"}
REPEAT_DAYS = {"daily": 1, "weekly": 7}
# How long after the start each firewall may still pick its task up (an offline firewall that comes back
# later does not upgrade in the middle of the working day). Minutes -> label.
WINDOWS = {60: "1 hour", 120: "2 hours", 240: "4 hours", 480: "8 hours", 1440: "24 hours"}


class ScheduleError(ValueError):
    pass


def parse_local(value: str) -> datetime:
    """A datetime-local form value ('2026-10-25T02:00'), in the console's time zone, as an aware datetime."""
    try:
        naive = datetime.strptime(value.strip()[:16], "%Y-%m-%dT%H:%M")
    except ValueError:
        raise ScheduleError("Enter a date and time") from None
    return naive.replace(tzinfo=display_timezone())


def local_input(value: datetime) -> str:
    """The value for a datetime-local field, in the console's time zone."""
    return aware(value).astimezone(display_timezone()).strftime("%Y-%m-%dT%H:%M")


def default_start(now: datetime | None = None) -> datetime:
    """2:00 AM tomorrow, local time: the usual maintenance window."""
    local = aware(now or utcnow()).astimezone(display_timezone())
    return (local + timedelta(days=1)).replace(hour=2, minute=0, second=0, microsecond=0)


def next_run(run_at: datetime, repeat: str, now: datetime) -> datetime:
    """The first repeat after `now`, at the same local wall-clock time (across daylight saving changes)."""
    step = timedelta(days=REPEAT_DAYS[repeat])
    local = aware(run_at).astimezone(display_timezone())
    while local <= now:
        # Aware + timedelta keeps the wall-clock time; normalizing re-applies the zone's offset.
        local = (local.replace(tzinfo=None) + step).replace(tzinfo=display_timezone())
    return local


def describe(job: ScheduledJob) -> str:
    targets = "all firewalls" if job.device_ids is None else f"{len(job.device_ids)} firewall(s)"
    return f"{BULK_ACTIONS.get(job.action, job.action)} on {targets}, {REPEATS.get(job.repeat, job.repeat).lower()}, " \
           f"from {format_dt(job.run_at)}"


def run_job(db: Session, settings: Settings, job: ScheduledJob, actor: str, now: datetime | None = None) -> str:
    """Queue the job's action on its firewalls now; record and return the summary."""
    now = now or utcnow()
    label = BULK_ACTIONS.get(job.action, job.action)
    window = timedelta(minutes=job.window_minutes or 240)
    try:
        result = run_bulk(db, settings, job.action, target_devices(db, job.device_ids), actor, pickup_window=window)
        job.last_result = result.as_dict(label)
    except TaskError as exc:
        job.last_result = {"queued": [], "skipped": {}, "refused": [], "summary": f"{label}: not run: {exc}."}
    job.last_run_at = now
    summary = job.last_result["summary"]
    audit(db, actor, "schedule.run", target=str(job.id), detail=f"{job.name}: {summary}"[:1000])
    return summary


def run_due_jobs(db: Session, settings: Settings, now: datetime | None = None) -> int:
    """Run every scheduled job whose time has come. A job the server missed by more than its window
    (it was down) is not run late; a repeating one moves on to its next time. Returns jobs run."""
    now = now or utcnow()
    ran = 0
    due = select(ScheduledJob).where(ScheduledJob.status == JobStatus.scheduled, ScheduledJob.run_at <= now)
    for job in db.scalars(due.order_by(ScheduledJob.run_at, ScheduledJob.id)).all():
        window = timedelta(minutes=job.window_minutes or 240)
        if now - aware(job.run_at) > window:
            job.last_run_at = now
            job.last_result = {"queued": [], "skipped": {}, "refused": [],
                               "summary": f"Missed: the server was not running at {format_dt(job.run_at)}."}
            log.warning("Scheduled job %s (%s) missed its window", job.id, job.name)
        else:
            run_job(db, settings, job, actor=f"schedule:{job.created_by or 'system'}", now=now)
            ran += 1
        if job.repeat in REPEAT_DAYS:
            job.run_at = next_run(job.run_at, job.repeat, now)
        else:
            job.status = JobStatus.done
    return ran
