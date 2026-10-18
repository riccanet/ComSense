from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Undefined
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import __version__
from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import (
    Alert,
    AuditLog,
    Backup,
    Device,
    DeviceStatus,
    EnrollmentKey,
    Metric,
    Organization,
    Policy,
    PolicyAssignment,
    PolicyType,
    Role,
    Task,
    TaskStatus,
    TaskType,
    User,
    aware,
    utcnow,
)
from ..security import (
    RateLimiter,
    generate_enrollment_key,
    hash_password,
    hash_secret,
    key_display_prefix,
    verify_password,
)
from ..enrollment import make_code
from ..services.agentpkg import latest_package
from ..services.appsettings import agent_tls_names, effective_agent_url, get_email_settings, setup_pending
from ..services.backups import delete_backup_file, load_backup
from ..services.policy_examples import EXAMPLES
from ..services.policies import PolicyError, desired_policies, policy_hash, validate_policy
from ..services.tasks import COMING_SOON, SAFE_TASKS, TASK_CAPABILITY, TaskError, queue_task
from ..tls import ensure_agent_tls
from .auth import csrf_token, current_user, flash, pop_flashes, require, verify_csrf

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

router = APIRouter(dependencies=[Depends(verify_csrf)])


def changes_allowed(user: User = Depends(current_user), settings: Settings = Depends(get_settings)) -> None:
    """Guard for actions that change firewalls; they are "coming soon" until enabled."""
    if not settings.enable_firewall_changes:
        raise HTTPException(403, COMING_SOON)


CHANGES = [Depends(changes_allowed)]
login_limiter = RateLimiter(limit=10, window_seconds=300)

viewer = require(Role.viewer)
operator = require(Role.operator)
admin = require(Role.admin)

# Tasks an operator can start from the device page, with a human label.
MANUAL_TASKS = {
    TaskType.backup: "Back up configuration now",
    TaskType.check_updates: "Check for updates",
    TaskType.refresh_inventory: "Refresh inventory",
    TaskType.upgrade_packages: "Upgrade all packages",
    TaskType.upgrade_system: "Upgrade pfSense (reboots)",
    TaskType.reboot: "Reboot",
}


def _ago(value) -> str:
    if value is None:
        return "never"
    delta = utcnow() - aware(value)
    secs = int(delta.total_seconds())
    if secs < 0:
        return "just now"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return f"{secs}s ago"


def _fmt_dt(value) -> str:
    return aware(value).strftime("%Y-%m-%d %H:%M UTC") if value else ""


def _fmt_bytes(value) -> str:
    # Agent reports are partial at times; missing keys arrive as jinja2.Undefined.
    if value is None or isinstance(value, Undefined):
        return ""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def _fmt_arch(value: str) -> str:
    names = {"amd64": "x86-64", "x86_64": "x86-64", "i386": "x86 (32-bit)", "arm64": "ARM64", "aarch64": "ARM64",
             "arm": "ARMv7", "armv7": "ARMv7", "armv6": "ARMv6"}
    return names.get(value, value)


TEMPLATES.env.filters["ago"] = _ago
TEMPLATES.env.filters["arch"] = _fmt_arch
TEMPLATES.env.filters["dt"] = _fmt_dt
TEMPLATES.env.filters["bytes"] = _fmt_bytes
TEMPLATES.env.filters["pretty_json"] = lambda v: json.dumps(v, indent=2, sort_keys=True)


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def valid_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value)) and len(value) <= 255


THEMES = ("light", "dark", "auto")
THEME_COOKIE = "csfm_theme"


def theme_preference(request: Request) -> str:
    """The viewer's chosen theme. It is rendered into <html data-theme> so there is no flash."""
    value = request.cookies.get(THEME_COOKIE, "auto")
    return value if value in THEMES else "auto"


def render(request: Request, template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    ctx.update(
        request=request,
        user=getattr(request.state, "user", None),
        csrf_token=csrf_token(request),
        flashes=pop_flashes(request),
        version=__version__,
        Role=Role,
        theme=theme_preference(request),
        changes_enabled=request.app.state.settings.enable_firewall_changes,
        safe_tasks=SAFE_TASKS,
    )
    return TEMPLATES.TemplateResponse(request, template, ctx, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _get_device(db: Session, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    return device


# --------------------------------------------------------------------------- auth


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)):
    return render(request, "login.html", email_ready=get_email_settings(db).configured)


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = _ip(request)
    if not login_limiter.allow(ip):
        flash(request, "Too many login attempts. Wait a few minutes and try again.", "error")
        return render(request, "login.html", status_code=429)
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None or not user.active or not verify_password(password, user.password_hash):
        audit(db, username[:64], "login.failed", ip=ip)
        db.commit()
        flash(request, "Invalid username or password.", "error")
        return render(request, "login.html", status_code=401)
    request.session.clear()
    request.session.update(uid=user.id, pwv=user.password_hash[-16:])
    user.last_login_at = utcnow()
    audit(db, user.username, "login", ip=ip)
    db.commit()
    if user.must_change_password:
        flash(request, "You signed in with a temporary password. Choose a new one to continue.", "warn")
        return redirect("/account")
    return redirect("/")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


@router.get("/account", response_class=HTMLResponse)
def account(request: Request, user: User = Depends(viewer)):
    return render(request, "account.html")


@router.post("/account/password")
def change_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    confirm: str = Form(...),
    user: User = Depends(viewer),
    db: Session = Depends(get_db),
):
    if not verify_password(current, user.password_hash):
        flash(request, "Current password is incorrect.", "error")
    elif new != confirm:
        flash(request, "New passwords do not match.", "error")
    elif len(new) < 12:
        flash(request, "Use at least 12 characters.", "error")
    elif new == current:
        flash(request, "Choose a password different from the current one.", "error")
    else:
        was_temporary = user.must_change_password
        user.password_hash = hash_password(new)
        user.must_change_password = False
        request.session["pwv"] = user.password_hash[-16:]
        audit(db, user.username, "user.password_changed", target=user.username, ip=_ip(request))
        db.commit()
        flash(request, "Password changed.", "success")
        if was_temporary:
            return redirect("/setup" if user.role == Role.admin and setup_pending(db) else "/")
    return redirect("/account")


# ---------------------------------------------------------------------- dashboard


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    if user.role == Role.admin and setup_pending(db) and not db.scalar(select(func.count()).select_from(Device)):
        return redirect("/setup")
    counts = dict(db.execute(select(Device.status, func.count()).group_by(Device.status)).all())
    alerts = db.scalars(
        select(Alert)
        .where(Alert.resolved_at.is_(None))
        .order_by(Alert.severity.asc(), Alert.opened_at.desc())
        .limit(50)
    ).all()
    devices = db.scalars(select(Device).order_by(Device.name)).all()
    updates = [d for d in devices if (d.updates or {}).get("update_available")]
    recent_tasks = db.scalars(select(Task).order_by(Task.id.desc()).limit(15)).all()
    return render(
        request,
        "dashboard.html",
        counts={s.value: counts.get(s, 0) for s in DeviceStatus},
        total=len(devices),
        customers=db.scalar(select(func.count()).select_from(Organization)),
        alerts=alerts,
        updates=updates,
        recent_tasks=recent_tasks,
    )


# ------------------------------------------------------------------------ devices


@router.get("/devices", response_class=HTMLResponse)
def devices(
    request: Request,
    org: str = "",
    q: str = "",
    user: User = Depends(viewer),
    db: Session = Depends(get_db),
):
    stmt = select(Device).order_by(Device.name)
    if org == "none":
        stmt = stmt.where(Device.organization_id.is_(None))
    elif org.isdigit():
        stmt = stmt.where(Device.organization_id == int(org))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            Device.name.ilike(like) | Device.hostname.ilike(like) | Device.wan_ip.ilike(like)
        )
    open_alerts = dict(
        db.execute(
            select(Alert.device_id, func.count()).where(Alert.resolved_at.is_(None)).group_by(Alert.device_id)
        ).all()
    )
    return render(
        request,
        "devices.html",
        devices=db.scalars(stmt).all(),
        orgs=db.scalars(select(Organization).order_by(Organization.name)).all(),
        org=org,
        q=q,
        open_alerts=open_alerts,
        bulk_tasks={t: MANUAL_TASKS[t] for t in (TaskType.backup, TaskType.check_updates, TaskType.refresh_inventory)},
    )


@router.post("/devices/bulk")
async def devices_bulk(
    request: Request, user: User = Depends(operator), db: Session = Depends(get_db)
):
    form = await request.form()
    ids = form.getlist("device_ids")
    try:
        ttype = TaskType(str(form.get("task_type", "")))
    except ValueError as exc:
        raise HTTPException(400, "Unknown task type") from exc
    if ttype not in (TaskType.backup, TaskType.check_updates, TaskType.refresh_inventory):
        raise HTTPException(400, "That task cannot be run in bulk")
    queued, skipped = 0, 0
    for device_id in ids:
        device = db.get(Device, str(device_id))
        if device is None:
            continue
        try:
            queue_task(db, device, ttype, actor=user.username)
            queued += 1
        except TaskError:
            skipped += 1
    audit(db, user.username, "task.bulk", detail=f"{ttype.value} x{queued}", ip=_ip(request))
    db.commit()
    flash(request, f"Queued {ttype.value} on {queued} device(s); skipped {skipped}.", "success")
    return redirect("/devices")


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(
    device_id: str, request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)
):
    device = _get_device(db, device_id)
    since = utcnow() - timedelta(hours=24)
    metrics = db.scalars(
        select(Metric).where(Metric.device_id == device.id, Metric.ts >= since).order_by(Metric.ts)
    ).all()
    tasks = db.scalars(
        select(Task).where(Task.device_id == device.id).order_by(Task.id.desc()).limit(50)
    ).all()
    backups = db.scalars(
        select(Backup).where(Backup.device_id == device.id).order_by(Backup.created_at.desc()).limit(100)
    ).all()
    alerts = db.scalars(
        select(Alert).where(Alert.device_id == device.id).order_by(Alert.opened_at.desc()).limit(50)
    ).all()
    desired = desired_policies(db, device)
    policy_state = [
        {
            "policy": p,
            "in_sync": (device.applied_policies or {}).get(str(p.id)) == policy_hash(p),
            "direct": any(a.device_id == device.id for a in p.assignments),
        }
        for p in desired
    ]
    assigned_ids = {p.id for p in desired}
    return render(
        request,
        "device.html",
        device=device,
        metrics=[
            {
                "ts": aware(m.ts).isoformat(),
                "cpu": m.cpu_pct,
                "mem": m.mem_pct,
                "states": m.states,
            }
            for m in metrics
        ],
        tasks=tasks,
        backups=backups,
        alerts=alerts,
        policy_state=policy_state,
        policy_names={str(p.id): p.name for p in db.scalars(select(Policy))} if device.rolled_back_policies else {},
        assignable=[
            p for p in db.scalars(select(Policy).order_by(Policy.name)) if p.id not in assigned_ids
        ],
        orgs=db.scalars(select(Organization).order_by(Organization.name)).all(),
        manual_tasks=MANUAL_TASKS,
        task_capability=TASK_CAPABILITY,
    )


@router.post("/devices/{device_id}/tasks")
def device_queue_task(
    device_id: str,
    request: Request,
    task_type: str = Form(...),
    package: str = Form(""),
    service: str = Form(""),
    settings: Settings = Depends(get_settings),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    try:
        ttype = TaskType(task_type)
    except ValueError as exc:
        raise HTTPException(400, "Unknown task type") from exc
    payload: dict[str, Any] = {}
    if ttype in (TaskType.install_package, TaskType.remove_package):
        if not package.startswith("pfSense-pkg-"):
            flash(request, "Package names start with pfSense-pkg-.", "error")
            return redirect(f"/devices/{device_id}")
        payload["package"] = package.strip()
    elif ttype == TaskType.restart_service:
        if not service.strip():
            flash(request, "Choose a service.", "error")
            return redirect(f"/devices/{device_id}")
        payload["service"] = service.strip()
    elif ttype not in MANUAL_TASKS:
        raise HTTPException(400, "This task cannot be started manually")
    try:
        task = queue_task(
            db, device, ttype, payload, actor=user.username, changes_enabled=settings.enable_firewall_changes
        )
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/devices/{device_id}")
    db.flush()
    audit(db, user.username, f"task.{ttype.value}", target=device.id, detail=json.dumps(payload), ip=_ip(request))
    db.commit()
    flash(request, f"Queued task #{task.id} ({ttype.value}). It runs at the next check-in.", "success")
    return redirect(f"/devices/{device_id}")


@router.post("/devices/{device_id}/rollbacks/clear")
def device_clear_rollbacks(
    device_id: str, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)
):
    device = _get_device(db, device_id)
    cleared = ", ".join(sorted(device.rolled_back_policies or {}))
    device.rolled_back_policies = {}
    now = utcnow()
    for alert in db.scalars(
        select(Alert).where(Alert.device_id == device.id, Alert.resolved_at.is_(None), Alert.key.like("rollback:%"))
    ):
        alert.resolved_at = now
        alert.acknowledged_by = alert.acknowledged_by or user.username
    audit(db, user.username, "device.rollbacks_cleared", target=device.id, detail=cleared, ip=_ip(request))
    db.commit()
    flash(request, "Cleared. The changes are sent again at the next check-in.", "success")
    return redirect(f"/devices/{device_id}")


@router.post("/devices/{device_id}/edit")
def device_edit(
    device_id: str,
    request: Request,
    name: str = Form(...),
    organization_id: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    device.name = name.strip()[:128] or device.name
    device.organization_id = int(organization_id) if organization_id.isdigit() else None
    device.notes = notes
    audit(db, user.username, "device.edited", target=device.id, ip=_ip(request))
    db.commit()
    flash(request, "Device updated.", "success")
    return redirect(f"/devices/{device_id}")


@router.post("/devices/{device_id}/status")
def device_set_status(
    device_id: str,
    request: Request,
    action: str = Form(...),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    if action == "approve" and device.status == DeviceStatus.pending:
        device.status = DeviceStatus.offline
    elif action == "disable":
        device.status = DeviceStatus.disabled
        for task in device.tasks:
            if task.status == TaskStatus.pending:
                task.status = TaskStatus.cancelled
    elif action == "enable" and device.status == DeviceStatus.disabled:
        device.status = DeviceStatus.offline
    else:
        raise HTTPException(400, "Invalid action for the device's current state")
    audit(db, user.username, f"device.{action}", target=device.id, ip=_ip(request))
    db.commit()
    flash(request, f"Device {action}d.", "success")
    return redirect(f"/devices/{device_id}")


@router.post("/devices/{device_id}/delete")
def device_delete(
    device_id: str,
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    for backup in device.backups:
        delete_backup_file(settings, backup)
    audit(db, user.username, "device.deleted", target=device.id, detail=device.name, ip=_ip(request))
    db.delete(device)
    db.commit()
    flash(request, "Device and its backups were deleted. Its token no longer works.", "success")
    return redirect("/devices")


@router.post("/devices/{device_id}/policies", dependencies=CHANGES)
def device_assign_policy(
    device_id: str,
    request: Request,
    policy_id: int = Form(...),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "Policy not found")
    db.add(PolicyAssignment(policy_id=policy.id, device_id=device.id))
    audit(db, user.username, "policy.assigned", target=device.id, detail=policy.name, ip=_ip(request))
    db.commit()
    flash(request, f"Assigned {policy.name}. It is applied at the next check-in.", "success")
    return redirect(f"/devices/{device_id}")


@router.post("/devices/{device_id}/policies/{policy_id}/unassign", dependencies=CHANGES)
def device_unassign_policy(
    device_id: str,
    policy_id: int,
    request: Request,
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    assignment = db.scalar(
        select(PolicyAssignment).where(
            PolicyAssignment.device_id == device_id, PolicyAssignment.policy_id == policy_id
        )
    )
    if assignment is None:
        flash(request, "That policy comes from a customer-wide or global assignment.", "error")
    else:
        db.delete(assignment)
        audit(db, user.username, "policy.unassigned", target=device_id, detail=str(policy_id), ip=_ip(request))
        db.commit()
        flash(request, "Policy unassigned. Items it created are removed at the next check-in.", "success")
    return redirect(f"/devices/{device_id}")


# ------------------------------------------------------------------- tasks/alerts


@router.get("/tasks/{task_id}", response_class=HTMLResponse)
def task_detail(task_id: int, request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(404, "Task not found")
    return render(request, "task.html", task=task)


@router.post("/tasks/{task_id}/cancel")
def task_cancel(task_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(404, "Task not found")
    if task.status == TaskStatus.pending:
        task.status = TaskStatus.cancelled
        task.finished_at = utcnow()
        audit(db, user.username, "task.cancelled", target=str(task.id), ip=_ip(request))
        db.commit()
        flash(request, "Task cancelled.", "success")
    else:
        flash(request, "Only tasks that have not been sent yet can be cancelled.", "error")
    return redirect(f"/devices/{task.device_id}")


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(
    request: Request, show: str = "open", user: User = Depends(viewer), db: Session = Depends(get_db)
):
    stmt = select(Alert).order_by(Alert.opened_at.desc()).limit(500)
    if show == "open":
        stmt = stmt.where(Alert.resolved_at.is_(None))
    return render(request, "alerts.html", alerts=db.scalars(stmt).all(), show=show)


@router.post("/alerts/{alert_id}/ack")
def alert_ack(alert_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "Alert not found")
    alert.acknowledged_by = user.username
    db.commit()
    return redirect(request.headers.get("referer") or "/alerts")


# ------------------------------------------------------------------------ backups


def _get_backup(db: Session, backup_id: int) -> Backup:
    backup = db.get(Backup, backup_id)
    if backup is None:
        raise HTTPException(404, "Backup not found")
    return backup


@router.get("/backups/{backup_id}/download")
def backup_download(
    backup_id: int,
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    backup = _get_backup(db, backup_id)
    data = load_backup(settings, backup)
    audit(db, user.username, "backup.downloaded", target=backup.device_id, detail=str(backup.id), ip=_ip(request))
    db.commit()
    host = re.sub(r"[^A-Za-z0-9.-]", "_", backup.device.hostname or "") or "pfsense"
    filename = f"config-{host}-{aware(backup.created_at):%Y%m%d%H%M%S}.xml"
    return Response(
        data,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/backups/{backup_id}/pin")
def backup_pin(backup_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    backup = _get_backup(db, backup_id)
    backup.pinned = not backup.pinned
    db.commit()
    return redirect(f"/devices/{backup.device_id}#backups")


@router.post("/backups/{backup_id}/delete")
def backup_delete(
    backup_id: int,
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    backup = _get_backup(db, backup_id)
    device_id = backup.device_id
    delete_backup_file(settings, backup)
    db.delete(backup)
    audit(db, user.username, "backup.deleted", target=device_id, detail=str(backup_id), ip=_ip(request))
    db.commit()
    flash(request, "Backup deleted.", "success")
    return redirect(f"/devices/{device_id}#backups")


@router.post("/backups/{backup_id}/restore", dependencies=CHANGES)
def backup_restore(
    backup_id: int,
    request: Request,
    confirm: str = Form(""),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    backup = _get_backup(db, backup_id)
    device = backup.device
    if confirm.strip() != device.name:
        flash(request, "Type the device name exactly to confirm the restore.", "error")
        return redirect(f"/devices/{device.id}#backups")
    try:
        task = queue_task(
            db,
            device,
            TaskType.restore_backup,
            {"backup_id": backup.id, "sha256": backup.sha256},
            actor=user.username,
            pickup_window=timedelta(hours=1),
            changes_enabled=True,  # the route itself is guarded by changes_allowed
        )
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/devices/{device.id}#backups")
    db.flush()
    audit(db, user.username, "backup.restore_queued", target=device.id, detail=f"backup={backup.id} task={task.id}", ip=_ip(request))
    db.commit()
    flash(request, "Restore queued. The firewall reboots after applying it.", "success")
    return redirect(f"/devices/{device.id}")


# ---------------------------------------------------------------- enrollment keys


@router.get("/keys", response_class=HTMLResponse)
def keys_page(
    request: Request,
    customer: int | None = None,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    tls = ensure_agent_tls(settings, extra_names=agent_tls_names(db))
    pin = tls.pin if tls.self_signed else None
    new_key = request.session.pop("new_key", None)
    agent_url = effective_agent_url(db, settings)
    package = latest_package(settings.data_dir / "downloads")
    return render(
        request,
        "keys.html",
        keys=db.scalars(select(EnrollmentKey).order_by(EnrollmentKey.id.desc())).all(),
        orgs=db.scalars(select(Organization).order_by(Organization.name)).all(),
        new_key=new_key,
        enrollment_code=make_code(agent_url, new_key, pin) if new_key else None,
        agent_url=agent_url,
        agent_pin=pin,
        agent_cert_expires=tls.not_after,
        preselect=customer,
        package=package,
        now=utcnow(),
    )


def create_enrollment_key(
    db: Session,
    user: User,
    name: str,
    organization_id: int | None = None,
    expires_days: int = 7,
    max_uses: int | None = None,
    require_approval: bool = False,
    ip: str = "",
) -> str:
    """Create a key and return its value; the caller commits and shows it once."""
    value = generate_enrollment_key()
    key = EnrollmentKey(
        name=name.strip()[:128] or "Enrollment key",
        prefix=key_display_prefix(value),
        key_hash=hash_secret(value),
        organization_id=organization_id,
        expires_at=utcnow() + timedelta(days=expires_days) if expires_days > 0 else None,
        max_uses=max_uses if max_uses and max_uses > 0 else None,
        require_approval=require_approval,
        created_by=user.username,
    )
    db.add(key)
    audit(db, user.username, "enrollment_key.created", target=key.prefix, detail=key.name, ip=ip)
    return value


@router.post("/keys")
def keys_create(
    request: Request,
    name: str = Form(...),
    organization_id: str = Form(""),
    expires_days: int = Form(7),
    max_uses: str = Form(""),
    require_approval: bool = Form(False),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    value = create_enrollment_key(
        db,
        user,
        name,
        organization_id=int(organization_id) if organization_id.isdigit() else None,
        expires_days=expires_days,
        max_uses=int(max_uses) if max_uses.isdigit() else None,
        require_approval=require_approval,
        ip=_ip(request),
    )
    db.commit()
    # Shown once, on the next page load only; never stored in clear text.
    request.session["new_key"] = value
    return redirect("/keys")


@router.post("/keys/{key_id}/revoke")
def keys_revoke(key_id: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    key = db.get(EnrollmentKey, key_id)
    if key is None:
        raise HTTPException(404, "Key not found")
    key.revoked = True
    audit(db, user.username, "enrollment_key.revoked", target=key.prefix, ip=_ip(request))
    db.commit()
    flash(request, "Key revoked. Firewalls already enrolled keep working.", "success")
    return redirect("/keys")


# ----------------------------------------------------------------------- policies


@router.get("/policies", response_class=HTMLResponse)
def policies_page(request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    return render(
        request,
        "policies.html",
        policies=db.scalars(select(Policy).order_by(Policy.name)).all(),
    )


@router.get("/policies/new", response_class=HTMLResponse)
def policy_new(
    request: Request,
    type: str = "aliases",
    settings: Settings = Depends(get_settings),
    user: User = Depends(operator),
):
    if not settings.enable_firewall_changes:
        return redirect("/policies")
    ptype = PolicyType(type) if type in PolicyType.__members__ else PolicyType.aliases
    return render(
        request,
        "policy_edit.html",
        policy=None,
        ptype=ptype,
        content=json.dumps(EXAMPLES[ptype], indent=2),
        types=list(PolicyType),
        examples={t.value: json.dumps(EXAMPLES[t], indent=2) for t in PolicyType},
    )


def _parse_policy_form(ptype_raw: str, content_raw: str) -> tuple[PolicyType, dict[str, Any]]:
    try:
        ptype = PolicyType(ptype_raw)
    except ValueError as exc:
        raise PolicyError("Unknown policy type") from exc
    try:
        content = json.loads(content_raw)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"Content is not valid JSON: {exc}") from exc
    validate_policy(ptype, content)
    return ptype, content


@router.post("/policies", dependencies=CHANGES)
def policy_create(
    request: Request,
    name: str = Form(...),
    type: str = Form(...),
    description: str = Form(""),
    content: str = Form(...),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    try:
        ptype, doc = _parse_policy_form(type, content)
    except PolicyError as exc:
        flash(request, str(exc), "error")
        return render(
            request,
            "policy_edit.html",
            status_code=400,
            policy=None,
            ptype=PolicyType(type) if type in PolicyType.__members__ else PolicyType.aliases,
            content=content,
            name=name,
            description=description,
            types=list(PolicyType),
            examples={},
        )
    policy = Policy(name=name.strip()[:128], type=ptype, description=description, content=doc, updated_by=user.username)
    db.add(policy)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        flash(request, "A policy with that name already exists.", "error")
        return redirect("/policies/new")
    audit(db, user.username, "policy.created", target=policy.name, ip=_ip(request))
    db.commit()
    flash(request, "Policy created. Assign it to firewalls or customers below.", "success")
    return redirect(f"/policies/{policy.id}")


@router.get("/policies/{policy_id}", response_class=HTMLResponse)
def policy_detail(
    policy_id: int,
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(viewer),
    db: Session = Depends(get_db),
):
    if not settings.enable_firewall_changes:
        return redirect("/policies")
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "Policy not found")
    digest = policy_hash(policy)
    targets = []
    for device in db.scalars(select(Device).order_by(Device.name)):
        if any(p.id == policy.id for p in desired_policies(db, device)):
            targets.append((device, (device.applied_policies or {}).get(str(policy.id)) == digest))
    return render(
        request,
        "policy_edit.html",
        policy=policy,
        ptype=policy.type,
        content=json.dumps(policy.content, indent=2),
        types=list(PolicyType),
        examples={},
        targets=targets,
        orgs=db.scalars(select(Organization).order_by(Organization.name)).all(),
        devices=db.scalars(select(Device).order_by(Device.name)).all(),
    )


@router.post("/policies/{policy_id}", dependencies=CHANGES)
def policy_update(
    policy_id: int,
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    content: str = Form(...),
    enabled: bool = Form(False),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "Policy not found")
    try:
        _, doc = _parse_policy_form(policy.type.value, content)
    except PolicyError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/policies/{policy_id}")
    if doc != policy.content:
        policy.revision += 1
    policy.name = name.strip()[:128] or policy.name
    policy.description = description
    policy.content = doc
    policy.enabled = enabled
    policy.updated_at = utcnow()
    policy.updated_by = user.username
    audit(db, user.username, "policy.updated", target=policy.name, detail=f"rev={policy.revision}", ip=_ip(request))
    db.commit()
    flash(request, f"Saved revision {policy.revision}. Assigned devices update at their next check-in.", "success")
    return redirect(f"/policies/{policy_id}")


@router.post("/policies/{policy_id}/delete", dependencies=CHANGES)
def policy_delete(policy_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)):
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "Policy not found")
    audit(db, user.username, "policy.deleted", target=policy.name, ip=_ip(request))
    db.delete(policy)
    db.commit()
    flash(request, "Policy deleted. Devices remove what it created at their next check-in.", "success")
    return redirect("/policies")


@router.post("/policies/{policy_id}/assign", dependencies=CHANGES)
def policy_assign(
    policy_id: int,
    request: Request,
    target: str = Form(...),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    policy = db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "Policy not found")
    kind, _, ident = target.partition(":")
    if kind == "all":
        assignment = PolicyAssignment(policy_id=policy.id, all_devices=True)
    elif kind == "org" and ident.isdigit() and db.get(Organization, int(ident)):
        assignment = PolicyAssignment(policy_id=policy.id, organization_id=int(ident))
    elif kind == "device" and db.get(Device, ident):
        assignment = PolicyAssignment(policy_id=policy.id, device_id=ident)
    else:
        raise HTTPException(400, "Invalid assignment target")
    db.add(assignment)
    try:
        audit(db, user.username, "policy.assigned", target=policy.name, detail=target, ip=_ip(request))
        db.commit()
        flash(request, "Assignment added.", "success")
    except IntegrityError:
        db.rollback()
        flash(request, "That assignment already exists.", "error")
    return redirect(f"/policies/{policy_id}")


@router.post("/assignments/{assignment_id}/delete", dependencies=CHANGES)
def assignment_delete(
    assignment_id: int, request: Request, user: User = Depends(operator), db: Session = Depends(get_db)
):
    assignment = db.get(PolicyAssignment, assignment_id)
    if assignment is None:
        raise HTTPException(404, "Assignment not found")
    policy_id = assignment.policy_id
    db.delete(assignment)
    audit(db, user.username, "policy.unassigned", target=str(policy_id), ip=_ip(request))
    db.commit()
    return redirect(f"/policies/{policy_id}")


# -------------------------------------------------------------------------- users


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    return render(request, "users.html", users=db.scalars(select(User).order_by(User.username)).all())


@router.post("/users")
def users_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("viewer"),
    email: str = Form(""),
    email_alerts: bool = Form(False),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    if len(password) < 12:
        flash(request, "Passwords need at least 12 characters.", "error")
        return redirect("/users")
    email = email.strip()
    if email and not valid_email(email):
        flash(request, "That is not a valid email address.", "error")
        return redirect("/users")
    # Passwords set by an admin are temporary: the user picks their own at first sign-in.
    db.add(
        User(
            username=username.strip()[:64],
            password_hash=hash_password(password),
            role=Role(role),
            email=email,
            email_alerts=email_alerts and bool(email),
            must_change_password=True,
        )
    )
    try:
        audit(db, user.username, "user.created", target=username, detail=role, ip=_ip(request))
        db.commit()
        flash(request, "User created.", "success")
    except IntegrityError:
        db.rollback()
        flash(request, "That username is taken.", "error")
    return redirect("/users")


@router.post("/users/{user_id}")
def users_update(
    user_id: int,
    request: Request,
    role: str = Form(...),
    active: bool = Form(False),
    password: str = Form(""),
    email: str = Form(""),
    email_alerts: bool = Form(False),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if target.id == user.id and (Role(role) != Role.admin or not active):
        flash(request, "You cannot demote or deactivate your own account.", "error")
        return redirect("/users")
    email = email.strip()
    if email and not valid_email(email):
        flash(request, "That is not a valid email address.", "error")
        return redirect("/users")
    target.role = Role(role)
    target.active = active
    target.email = email
    target.email_alerts = email_alerts and bool(email)
    if password:
        if len(password) < 12:
            flash(request, "Passwords need at least 12 characters.", "error")
            return redirect("/users")
        target.password_hash = hash_password(password)
        target.must_change_password = True
    audit(db, user.username, "user.updated", target=target.username, detail=f"role={role} active={active}", ip=_ip(request))
    db.commit()
    flash(request, "User updated.", "success")
    return redirect("/users")


# -------------------------------------------------------------------------- audit


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    entries = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(500)).all()
    return render(request, "audit.html", entries=entries)
