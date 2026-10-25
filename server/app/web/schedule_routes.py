"""Scheduled jobs: run a bulk action (updates, backups, ...) on firewalls at a set time, once or repeating."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..db import get_db
from ..models import Device, JobStatus, Organization, Role, ScheduledJob, User, utcnow
from ..services.appsettings import display_timezone
from ..services.bulk import BULK_ACTIONS, available_actions
from ..services.schedules import (
    REPEATS,
    WINDOWS,
    ScheduleError,
    default_start,
    describe,
    local_input,
    parse_local,
    run_job,
)
from .auth import flash, require, verify_csrf
from .routes import _ip, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
viewer = require(Role.viewer)
operator = require(Role.operator)


def _get(db: Session, job_id: int) -> ScheduledJob:
    job = db.get(ScheduledJob, job_id)
    if job is None:
        raise HTTPException(404, "Scheduled job not found")
    return job


def _all_devices(db: Session) -> list[Device]:
    return list(db.scalars(select(Device).outerjoin(Organization, Device.organization_id == Organization.id)
                           .order_by(Organization.name.is_(None), Organization.name, Device.name)))


def _form(request: Request, db: Session, values: dict[str, Any], job: ScheduledJob | None = None,
          error: str = "", status_code: int = 200):
    return render(request, "schedule_form.html", status_code=status_code, job=job, values=values, error=error,
                  actions=available_actions(request.app.state.settings), repeats=REPEATS, windows=WINDOWS,
                  devices=_all_devices(db), tz_name=str(display_timezone()))


def _defaults(action: str = "", device_ids: list[str] | None = None) -> dict[str, Any]:
    return {"name": "", "action": action, "device_ids": device_ids or [], "all_devices": False,
            "run_at": local_input(default_start()), "repeat": "", "window": 240}


def _read(form) -> dict[str, Any]:
    """The submitted form as values; raises ScheduleError when something is wrong."""
    return {
        "name": str(form.get("name", "")).strip()[:128],
        "action": str(form.get("action", "")),
        "device_ids": [str(i) for i in form.getlist("device_ids")],
        "all_devices": form.get("all_devices") == "1",
        "run_at": str(form.get("run_at", "")),
        "repeat": str(form.get("repeat", "")),
        "window": str(form.get("window", "240")),
    }


def _validate(request: Request, values: dict[str, Any]) -> dict[str, Any]:
    if values["action"] not in available_actions(request.app.state.settings):
        raise ScheduleError("Choose a task")
    if values["repeat"] not in REPEATS:
        raise ScheduleError("Choose how often it runs")
    try:
        window = int(values["window"])
    except ValueError:
        window = 0
    if window not in WINDOWS:
        raise ScheduleError("Choose a window")
    if not values["all_devices"] and not values["device_ids"]:
        raise ScheduleError("Choose the firewalls, or All firewalls")
    run_at = parse_local(values["run_at"])
    if run_at < utcnow() - timedelta(minutes=1):
        raise ScheduleError("The start time is in the past")
    return {
        "name": values["name"] or BULK_ACTIONS[values["action"]],
        "action": values["action"],
        "device_ids": None if values["all_devices"] else values["device_ids"],
        "run_at": run_at,
        "repeat": values["repeat"],
        "window_minutes": window,
    }


@router.get("/schedules", response_class=HTMLResponse)
def schedules(request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    jobs = db.scalars(select(ScheduledJob).order_by(ScheduledJob.status != JobStatus.scheduled,
                                                    ScheduledJob.run_at, ScheduledJob.id.desc())).all()
    upcoming = [j for j in jobs if j.status == JobStatus.scheduled]
    past = sorted((j for j in jobs if j.status != JobStatus.scheduled),
                  key=lambda j: j.last_run_at or j.created_at, reverse=True)[:50]
    names = {d.id: d.name for d in db.scalars(select(Device))}
    return render(request, "schedules.html", upcoming=upcoming, past=past, actions=BULK_ACTIONS,
                  repeats=REPEATS, windows=WINDOWS, names=names)


@router.get("/schedules/new", response_class=HTMLResponse)
def schedule_new(request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    return _form(request, db, _defaults())


@router.post("/schedules/new", response_class=HTMLResponse)
async def schedule_new_from_selection(request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    """Schedule… on the Firewalls page: the form, with the selected firewalls and task filled in."""
    form = await request.form()
    action = str(form.get("task_type", ""))
    return _form(request, db, _defaults(action if action in BULK_ACTIONS else "",
                                        [str(i) for i in form.getlist("device_ids")]))


@router.post("/schedules", response_class=HTMLResponse)
async def schedule_create(request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    values = _read(await request.form())
    try:
        clean = _validate(request, values)
    except ScheduleError as exc:
        return _form(request, db, values, error=str(exc), status_code=400)
    job = ScheduledJob(**clean, created_by=user.username)
    db.add(job)
    db.flush()
    audit(db, user.username, "schedule.create", target=str(job.id), detail=describe(job)[:1000], ip=_ip(request))
    db.commit()
    flash(request, f"Scheduled: {describe(job)}.", "success")
    return redirect("/schedules")


@router.get("/schedules/{job_id}", response_class=HTMLResponse)
def schedule_edit(job_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    job = _get(db, job_id)
    values = {"name": job.name, "action": job.action, "device_ids": job.device_ids or [],
              "all_devices": job.device_ids is None, "run_at": local_input(job.run_at), "repeat": job.repeat,
              "window": job.window_minutes}
    return _form(request, db, values, job=job)


@router.post("/schedules/{job_id}", response_class=HTMLResponse)
async def schedule_update(job_id: int, request: Request, user: User = Depends(operator),
                          db: Session = Depends(get_db)):
    job = _get(db, job_id)
    values = _read(await request.form())
    try:
        clean = _validate(request, values)
    except ScheduleError as exc:
        return _form(request, db, values, job=job, error=str(exc), status_code=400)
    for key, value in clean.items():
        setattr(job, key, value)
    job.status = JobStatus.scheduled  # saving a finished or cancelled job schedules it again
    audit(db, user.username, "schedule.update", target=str(job.id), detail=describe(job)[:1000], ip=_ip(request))
    db.commit()
    flash(request, f"Saved: {describe(job)}.", "success")
    return redirect("/schedules")


@router.post("/schedules/{job_id}/run")
def schedule_run_now(job_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    """Run the job's action now; its schedule is unchanged."""
    job = _get(db, job_id)
    summary = run_job(db, request.app.state.settings, job, actor=user.username)
    db.commit()
    flash(request, summary, "success")
    return redirect("/schedules")


@router.post("/schedules/{job_id}/cancel")
def schedule_cancel(job_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    job = _get(db, job_id)
    if job.status == JobStatus.scheduled:
        job.status = JobStatus.cancelled
        audit(db, user.username, "schedule.cancel", target=str(job.id), detail=job.name, ip=_ip(request))
        db.commit()
        flash(request, f"Cancelled: {job.name}. Tasks it already queued are not affected.", "success")
    return redirect("/schedules")


@router.post("/schedules/{job_id}/delete")
def schedule_delete(job_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    job = _get(db, job_id)
    if job.status == JobStatus.scheduled:
        flash(request, "Cancel the job before removing it.", "error")
        return redirect("/schedules")
    audit(db, user.username, "schedule.delete", target=str(job.id), detail=job.name, ip=_ip(request))
    db.delete(job)
    db.commit()
    flash(request, f"Removed: {job.name}.", "success")
    return redirect("/schedules")
