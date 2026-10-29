from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Undefined
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from .. import __version__
from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db, session_factory
from ..models import (
    SsoProvider,
    DeviceGroup,
    Alert,
    TerminalSession,
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
from ..services.agentpkg import agent_outdated, latest_package
from ..services.alerts import CATEGORIES, category_filter, category_of
from ..services.appsettings import agent_tls_names, effective_agent_url, format_dt, get_email_settings, setup_pending
from ..services import neighbors as neighbors_svc
from ..services.bulk import BULK_ACTIONS, available_actions, check_now, run_bulk, target_devices, update_agent
from ..services.backups import BackupError, delete_backup_file, load_backup
from ..services.logview import LINE_CHOICES, LOGS, parse_filter_line, parse_line
from ..services.configview import config_summary, current_backup, is_system_alias, redact
from ..services.policies import (
    ALIAS_FORM_TYPES,
    TYPE_LABELS,
    PolicyError,
    desired_policies,
    parse_alias_entries,
    policy_hash,
    validate_alias,
    validate_port_forward_rule,
)
from ..services.tasks import (
    COMING_SOON,
    OPEN_STATES,
    SAFE_TASKS,
    TASK_CAPABILITY,
    TaskError,
    queue_task,
    task_progress,
    task_title,
)
from ..api.agent import wan_addresses
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
# Failed passwords per username, whatever address they come from (behind a proxy that passes
# X-Forwarded-For through, the address can be forged).
failed_login_limiter = RateLimiter(limit=20, window_seconds=900)
_dummy_hash: list[str] = []


def _password_matches(user: User | None, password: str) -> bool:
    """Checks the password, taking as long for an unknown username as for a known one."""
    if user is None:
        if not _dummy_hash:
            _dummy_hash.append(hash_password(secrets.token_urlsafe(16)))
        verify_password(password, _dummy_hash[0])
        return False
    return verify_password(password, user.password_hash)

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
    TaskType.free_disk_space: "Free disk space (package cache, old logs)",
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
    return format_dt(value)


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


def _fmt_isodate(value) -> str:
    """An ISO 8601 time reported by an agent, as '2026-10-18 2:40 PM CDT (2m ago)'."""
    try:
        when = datetime.fromisoformat(str(value))
    except ValueError:
        return "unknown"
    return f"{_fmt_dt(when)} ({_ago(when)})"


TEMPLATES.env.filters["ago"] = _ago
TEMPLATES.env.filters["isodate"] = _fmt_isodate
TEMPLATES.env.filters["agent_outdated"] = agent_outdated
TEMPLATES.env.filters["arch"] = _fmt_arch
TEMPLATES.env.filters["dt"] = _fmt_dt
TEMPLATES.env.filters["wan_ips"] = lambda device: wan_addresses((device.inventory or {}).get("interfaces") or []) \
    or ([device.wan_ip] if device.wan_ip else [])
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


def pending_devices(user: User | None) -> list[Device]:
    """Firewalls waiting for approval, for the banner admins see under the navigation bar."""
    if user is None or user.role != Role.admin:
        return []
    with session_factory()() as db:
        devices = db.scalars(select(Device).where(Device.status == DeviceStatus.pending)
                             .options(selectinload(Device.organization)).order_by(Device.enrolled_at)).all()
        db.expunge_all()
        return list(devices)


def render(request: Request, template: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
    user = getattr(request.state, "user", None)
    ctx.setdefault("pending_devices", pending_devices(user))
    ctx.update(
        request=request,
        user=user,
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


def local_path(value: str | None, default: str) -> str:
    """A page of this console to go back to (never another site, nor the banner fragment)."""
    if not value or not value.startswith("/") or value.startswith(("//", "/\\", "/pending-banner")):
        return default
    return value


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
    providers = db.scalars(select(SsoProvider).where(SsoProvider.enabled.is_(True)).order_by(SsoProvider.name)).all()
    return render(request, "login.html", email_ready=get_email_settings(db).configured, sso_providers=providers)


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
    account = username.strip().lower()[:64]
    if failed_login_limiter.blocked(account):
        audit(db, username[:64], "login.locked", detail="too many failed passwords", ip=ip)
        db.commit()
        flash(request, "Too many failed sign-ins for this account. Wait 15 minutes and try again.", "error")
        return render(request, "login.html", status_code=429)
    user = db.scalar(select(User).where(User.username == username.strip()))
    if not _password_matches(user, password) or not user.active:
        failed_login_limiter.allow(account)
        audit(db, username[:64], "login.failed", ip=ip)
        db.commit()
        flash(request, "Invalid username or password.", "error")
        return render(request, "login.html", status_code=401)
    request.session.clear()
    from .mfa_routes import begin_second_factor  # noqa: PLC0415 - avoids an import cycle

    if begin_second_factor(request, db, user):
        audit(db, user.username, "login.password_ok", detail="second factor required", ip=ip)
        db.commit()
        return redirect("/login/mfa")
    return complete_login(request, db, user)


def complete_login(request: Request, db: Session, user: User, method: str = "") -> RedirectResponse:
    """Sign the user in (after the password and, if they use one, the second factor)."""
    request.session.clear()
    request.session.update(uid=user.id, pwv=user.password_hash[-16:])
    user.last_login_at = utcnow()
    audit(db, user.username, "login", detail=f"mfa={method}" if method else "", ip=_ip(request))
    db.commit()
    if user.must_change_password:
        flash(request, "You signed in with a temporary password. Choose a new one to continue.", "warn")
        return redirect("/account")
    return redirect("/")


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


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
    # By customer, then firewall; firewalls without a customer last.
    stmt = (select(Device).outerjoin(Organization, Device.organization_id == Organization.id)
            .order_by(Organization.name.is_(None), func.lower(Organization.name), func.lower(Device.name)))
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
        latest_agent=_latest_agent_version(request),
        bulk_tasks=available_actions(request.app.state.settings),
    )


@router.post("/devices/bulk")
async def devices_bulk(
    request: Request, user: User = Depends(operator), db: Session = Depends(get_db)
):
    form = await request.form()
    ids = [str(i) for i in form.getlist("device_ids")]
    action = str(form.get("task_type", ""))
    label = BULK_ACTIONS.get(action, action)
    try:
        result = run_bulk(db, request.app.state.settings, action, target_devices(db, ids), user.username)
    except TaskError as exc:
        flash(request, f"{label}: {exc}.", "error")
        return redirect("/devices")
    summary = result.summary(label)
    audit(db, user.username, "task.bulk", detail=f"{action}: {summary}"[:1000], ip=_ip(request))
    db.commit()
    if action == "latest_branch" and result.queued:
        summary += " Each firewall checks for updates on its new branch afterwards."
    flash(request, summary, "success")
    return redirect("/devices")


@router.get("/pending-banner", response_class=HTMLResponse)
def pending_banner(request: Request, page: str = "/", user: User = Depends(viewer)):
    """The approval banner alone, polled by static/app.js so a new firewall shows up without a reload.
    `page` is the page it is shown on, where Approve and Reject return to."""
    return TEMPLATES.TemplateResponse(request, "_pending_banner.html", {
        "request": request, "csrf_token": csrf_token(request), "pending_devices": pending_devices(user),
        "banner_page": local_path(page, "/")})


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(
    device_id: str, request: Request, find: str = "", user: User = Depends(viewer), db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    find = find.strip()[:100]
    network = neighbors_svc.device_entries(device, find)
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
        latest_agent=_latest_agent_version(request),
        page_token=_device_page_token(db, device),
        task_banner=_task_banner(db, device),
        device_groups=db.scalars(
            select(DeviceGroup).where(DeviceGroup.devices.any(Device.id == device.id)).order_by(DeviceGroup.name)
        ).all(),
        type_labels=TYPE_LABELS,
        find=find,
        leases=neighbors_svc.by_ip(network["leases"]),
        lease_total=len((device.neighbors or {}).get("leases") or []),
        find_arp=neighbors_svc.by_ip(network["arp"]) if find else [],
        find_static=neighbors_svc.by_ip(network["static"]) if find else [],
        terminal_sessions=db.scalars(
            select(TerminalSession).where(TerminalSession.device_id == device.id)
            .order_by(TerminalSession.created_at.desc()).limit(10)
        ).all() if user.role == Role.admin else [],
        assignable=[
            p for p in db.scalars(select(Policy).order_by(Policy.name)) if p.id not in assigned_ids
        ],
        manual_tasks=MANUAL_TASKS,
        task_capability=TASK_CAPABILITY,
    )


CONFIG_PAGE_TASKS = (TaskType.nat_add, TaskType.nat_remove, TaskType.nat_edit, TaskType.alias_add,
                     TaskType.alias_edit, TaskType.alias_remove, TaskType.notifications, TaskType.ddns_add,
                     TaskType.ddns_edit, TaskType.ddns_remove, TaskType.update_branch)
# Offered when the firewall has not reported its own list yet (agent 0.2.7 and earlier).
DDNS_PROVIDERS = [
    ("cloudflare", "Cloudflare"), ("cloudflare-v6", "Cloudflare (v6)"), ("custom", "Custom"),
    ("custom-v6", "Custom (v6)"), ("dnsimple", "DNSimple"), ("duckdns", "DuckDNS"), ("dyndns", "DynDNS (dynamic)"),
    ("freedns", "freeDNS (afraid.org)"), ("godaddy", "GoDaddy"), ("he-net", "HE.net"), ("namecheap", "Namecheap"),
    ("noip", "No-IP"), ("noip-free", "No-IP (free)"), ("route53", "Route 53"),
]


@router.get("/devices/{device_id}/configuration", response_class=HTMLResponse)
def device_configuration(
    device_id: str, request: Request, edit_nat: str = "", edit_alias: str = "", edit_ddns: str = "",
    rules: str = "", user: User = Depends(viewer), db: Session = Depends(get_db),
):
    """The firewall's aliases, rules (read only), port forwards, services, packages, email notifications and
    notes; changed one at a time (Configurations deploys them to many firewalls)."""
    device = _get_device(db, device_id)
    backup = current_backup(db, device)
    summary: dict[str, Any] = {"nat": [], "aliases": [], "smtp": None, "rules": [], "rule_tabs": []}
    error = ""
    if backup is not None:
        try:
            summary = config_summary(request.app.state.settings, backup)
        except (BackupError, OSError) as exc:
            error = str(exc)
    queued = db.scalars(select(Task).where(
        Task.device_id == device.id, Task.status.in_(OPEN_STATES), Task.type.in_(CONFIG_PAGE_TASKS))).all()
    queued_packages = db.scalars(select(Task).where(
        Task.device_id == device.id, Task.status.in_(OPEN_STATES),
        Task.type.in_((TaskType.install_package, TaskType.remove_package)))).all()
    managed_aliases = {a.get("name") for p in desired_policies(db, device) if p.type == PolicyType.aliases
                       for a in (p.content or {}).get("aliases", [])}
    aliases = [a | {"managed": a["name"] in managed_aliases} for a in summary["aliases"]]
    ddns_inv = (device.inventory or {}).get("ddns")
    ddns_inv = ddns_inv if isinstance(ddns_inv, dict) else {}
    ddns_status = {c.get("fingerprint"): c for c in ddns_inv.get("clients", []) if isinstance(c, dict)}
    form_error = request.session.pop("form_error", None)
    # Changes the firewall made since the configuration shown was saved: the page shows them once the
    # firewall sends its new config.xml (the next check-in, then the backup upload).
    applied: list[Task] = []
    if backup is not None:
        applied = db.scalars(select(Task).where(
            Task.device_id == device.id, Task.status == TaskStatus.success, Task.type.in_(CONFIG_PAGE_TASKS),
            Task.finished_at > backup.created_at)).all()
    tabs = summary["rule_tabs"]
    # Open on the tab asked for, else LAN (where most rules are), else the first with rules.
    tab = next((t["id"] for t in tabs if t["id"] == rules), None) \
        or next((t["id"] for t in tabs if t["id"] == "lan" and t["count"]), None) \
        or next((t["id"] for t in tabs if t["count"]), tabs[0]["id"] if tabs else "")
    return render(
        request,
        "device_configuration.html",
        device=device,
        page_token=_device_page_token(db, device),
        task_banner=_task_banner(db, device),
        config_backup=backup,
        config_error=error,
        nat_rules=summary["nat"],
        nat_removing={t.payload.get("fingerprint") for t in queued if t.type == TaskType.nat_remove},
        nat_adding=[t.payload.get("rule", {}) for t in queued if t.type == TaskType.nat_add],
        nat_editing={t.payload.get("fingerprint") for t in queued if t.type == TaskType.nat_edit},
        edit_nat=edit_nat,
        be_removing={t.payload.get("name") for t in db.scalars(select(Task).where(
            Task.device_id == device.id, Task.status.in_(OPEN_STATES), Task.type == TaskType.be_destroy))},
        nat_applied={t.payload.get("fingerprint") for t in applied if t.type in (TaskType.nat_edit, TaskType.nat_remove)},
        applied_changes=applied,
        form_error=form_error,
        aliases=[a for a in aliases if not is_system_alias(a)],
        system_aliases=[a for a in aliases if is_system_alias(a)],
        rule_tabs=tabs,
        rule_tab=tab,
        rules=[r for r in summary["rules"] if r["tab"] == tab],
        interface_names={i["id"]: i["name"] for i in summary.get("interfaces", [])},
        package_tasks={t.payload.get("package"): t.type for t in queued_packages},
        alias_adding=[t.payload.get("alias", {}) for t in queued if t.type == TaskType.alias_add],
        alias_queued={t.payload.get("alias", {}).get("name") if t.type == TaskType.alias_edit else t.payload.get("name"):
                      "change" if t.type == TaskType.alias_edit else "removal"
                      for t in queued if t.type in (TaskType.alias_edit, TaskType.alias_remove)},
        edit_alias=edit_alias,
        alias_types=ALIAS_FORM_TYPES,
        smtp=summary["smtp"],
        smtp_pending=next((t.payload.get("smtp") for t in queued if t.type == TaskType.notifications), None),
        ddns=[d | {"status": ddns_status.get(d["fingerprint"], {})} for d in summary.get("ddns", [])],
        ddns_adding=[t.payload.get("entry", {}) for t in queued if t.type == TaskType.ddns_add],
        ddns_queued={t.payload.get("fingerprint"): "change" if t.type == TaskType.ddns_edit else "removal"
                     for t in queued if t.type in (TaskType.ddns_edit, TaskType.ddns_remove)},
        edit_ddns=edit_ddns,
        ddns_providers=[(p.get("value", ""), p.get("name", "")) for p in ddns_inv.get("providers", [])
                        if isinstance(p, dict)] or DDNS_PROVIDERS,
        update_branch=(device.inventory or {}).get("update_branch") or {},
        branch_pending=next((t.payload.get("branch") for t in queued if t.type == TaskType.update_branch), None),
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
    back = {TaskType.restart_service.value: f"/devices/{device_id}/configuration#services",
            TaskType.install_package.value: f"/devices/{device_id}/configuration#packages",
            TaskType.remove_package.value: f"/devices/{device_id}/configuration#packages"}.get(
                task_type, f"/devices/{device_id}")
    try:
        ttype = TaskType(task_type)
    except ValueError as exc:
        raise HTTPException(400, "Unknown task type") from exc
    payload: dict[str, Any] = {}
    if ttype in (TaskType.install_package, TaskType.remove_package):
        if not package.startswith("pfSense-pkg-"):
            flash(request, "Package names start with pfSense-pkg-.", "error")
            return redirect(back)
        if ttype == TaskType.remove_package and package.strip() == "pfSense-pkg-ComSense":
            flash(request, "The ComSense agent cannot remove itself; remove it in Package Manager on the firewall.",
                  "error")
            return redirect(back)
        payload["package"] = package.strip()
    elif ttype == TaskType.restart_service:
        if not service.strip():
            flash(request, "Choose a service.", "error")
            return redirect(back)
        payload["service"] = service.strip()
    elif ttype not in MANUAL_TASKS:
        raise HTTPException(400, "This task cannot be started manually")
    try:
        task = queue_task(
            db, device, ttype, payload, actor=user.username, changes_enabled=settings.enable_firewall_changes
        )
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(back)
    db.flush()
    audit(db, user.username, f"task.{ttype.value}", target=device.id, detail=json.dumps(payload), ip=_ip(request))
    db.commit()
    flash(request, f"Queued task #{task.id} ({ttype.value}). It runs at the next check-in.", "success")
    return redirect(back)


def _latest_agent_version(request: Request) -> str:
    package = latest_package(request.app.state.settings.data_dir / "downloads")
    return package["version"] if package else ""


# Shared with the API (services/apiops.py) and scheduled jobs.
_check_now = check_now
_update_agent = update_agent


def _active_tasks(db: Session, device: Device) -> list[Task]:
    """Tasks queued for or running on the firewall (the banner at the top of its pages), oldest first."""
    return list(db.scalars(select(Task).where(
        Task.device_id == device.id, Task.status.in_(OPEN_STATES),
        Task.type.not_in((TaskType.open_terminal, TaskType.read_logs)),  # the logs page shows its own
    ).order_by(Task.id)))


def _task_banner(db: Session, device: Device) -> list[dict[str, Any]]:
    out = []
    for t in _active_tasks(db, device):
        progress = task_progress(t)
        if t.type == TaskType.upgrade_system and t.status == TaskStatus.running and device.status == DeviceStatus.offline:
            # Out of touch mid-upgrade: it is rebooting (or installing at boot).
            progress = {"percent": max(92, progress["percent"] if progress else 0),
                        "step": "Rebooting; waiting for the firewall to come back"}
        out.append({"id": t.id, "title": task_title(t), "status": t.status.value, "progress": progress,
                    "since": t.sent_at or t.created_at})
    return out


def _device_page_token(db: Session, device: Device) -> str:
    """Changes when something the firewall's page shows changes because of the firewall: a task
    moves on, the agent version, status, capabilities or a check-in's inventory. Not on every
    check-in, so an idle page is left alone."""
    tasks = db.execute(
        select(Task.id, Task.status).where(Task.device_id == device.id).order_by(Task.id.desc()).limit(30)
    ).all()
    newest_backup = db.scalar(select(func.max(Backup.id)).where(Backup.device_id == device.id))
    # A running upgrade's progress too, so the banner at the top follows it.
    progress = [f"{t.id}:{p['percent']}" for t in _active_tasks(db, device) if (p := task_progress(t))]
    # The configuration too: after a change the page shows the firewall's new config.xml once it arrives.
    parts = [str(device.agent_version), device.status.value, ",".join(device.capabilities or []),
             str(device.product_version), ";".join(f"{t.id}:{t.status.value}" for t in tasks),
             str(device.config_sha256), str(newest_backup), ",".join(progress)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


@router.get("/devices/{device_id}/logs", response_class=HTMLResponse)
def device_logs(device_id: str, request: Request, task: int = 0, user: User = Depends(operator),
                db: Session = Depends(get_db)):
    """A log from the firewall, fetched on demand (read_logs) and searched on the firewall."""
    device = _get_device(db, device_id)
    fetched = db.get(Task, task) if task else None
    if fetched is not None and (fetched.device_id != device.id or fetched.type != TaskType.read_logs):
        fetched = None
    if fetched is None:  # the last fetch, so the page keeps showing it
        fetched = db.scalar(select(Task).where(Task.device_id == device.id, Task.type == TaskType.read_logs)
                            .order_by(Task.id.desc()).limit(1))
    params = (fetched.payload if fetched else None) or {"log": "system", "lines": 250, "search": ""}
    result = fetched.result if fetched is not None and fetched.status == TaskStatus.success else {}
    iface_names = {i.get("if"): (i.get("descr") or i.get("name")) for i in (device.inventory or {}).get("interfaces", [])
                   if isinstance(i, dict) and i.get("if")}
    rows: list[dict[str, Any]] = []
    for line in reversed(result.get("lines") or []):  # newest first, as pfSense shows logs
        if not isinstance(line, str):
            continue
        if params.get("log") == "firewall":
            row = parse_filter_line(line)
            row["interface"] = iface_names.get(row["interface"], row["interface"])
        else:
            row = parse_line(line)
        rows.append(row)
    return render(request, "device_logs.html", device=device, page_token=_device_page_token(db, device),
                  logs=LOGS, line_choices=LINE_CHOICES, params=params, fetched=fetched, result=result, rows=rows)


@router.post("/devices/{device_id}/logs")
def device_logs_fetch(device_id: str, request: Request, log: str = Form("system"), lines: int = Form(250),
                      search: str = Form(""), user: User = Depends(operator), db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    if log not in LOGS or lines not in LINE_CHOICES:
        raise HTTPException(400, "Unknown log or line count")
    try:
        task = queue_task(db, device, TaskType.read_logs, {"log": log, "lines": lines, "search": search.strip()[:200]},
                          actor=user.username)
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/devices/{device_id}/logs")
    db.commit()
    return redirect(f"/devices/{device_id}/logs?task={task.id}")


@router.get("/devices/{device_id}/poll")
def device_poll(device_id: str, user: User = Depends(viewer), db: Session = Depends(get_db)) -> dict[str, str]:
    """Polled by the firewall's page (static/app.js), which reloads itself when the token changes."""
    return {"token": _device_page_token(db, _get_device(db, device_id))}


def _queue_change(request: Request, db: Session, settings: Settings, device: Device, user: User, ttype: TaskType,
                  payload: dict[str, Any], what: str, anchor: str = ""):
    """Queue one change made on the firewall's Configuration page and go back there."""
    back = f"/devices/{device.id}/configuration{anchor}"
    try:
        queue_task(db, device, ttype, payload, actor=user.username, changes_enabled=settings.enable_firewall_changes)
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(back)
    audit(db, user.username, f"task.{ttype.value}", target=device.id, detail=what, ip=_ip(request))
    db.commit()
    flash(request, f"Queued: {what}. The firewall applies it within seconds and keeps the change only if it can "
          "still reach ComSense afterwards.", "success")
    return redirect(back)


def _port_forward_from_form(form) -> dict[str, Any]:
    """One port forward from the add or edit form on the firewall's page (raises PolicyError)."""
    from .config_routes import parse_endpoint

    dstport = str(form.get("dstport", "")).strip()
    # For a range (8000-8100) the internal port is where it starts, as on pfSense's own page.
    first_port = re.split(r"[:-]", dstport)[0] if re.fullmatch(r"[0-9]+[:-][0-9]+", dstport) else dstport
    rule = {
        "interface": str(form.get("interface", "wan")).strip().lower() or "wan",
        "protocol": str(form.get("protocol", "tcp")),
        "source": parse_endpoint(str(form.get("src", "")), str(form.get("srcport", ""))),
        "destination": parse_endpoint(str(form.get("dst", "")) or "wan address", dstport),
        "target": str(form.get("target", "")).strip(),
        "local_port": str(form.get("localport", "")).strip() or first_port,
        "descr": str(form.get("descr", "")).strip()[:200],
    }
    if form.get("disabled") == "true":
        rule["disabled"] = True
    try:
        validate_port_forward_rule(rule)
    except PolicyError as exc:
        raise PolicyError(str(exc).replace("rules[0].", "")) from exc
    return rule


def _nat_form_values(form) -> dict[str, Any]:
    """What was typed into a port forward form, under the names the form fills itself from (nat_fields)."""
    return {"interface": str(form.get("interface", "")), "protocol": str(form.get("protocol", "")),
            "src": str(form.get("src", "")), "src_port": str(form.get("srcport", "")),
            "destination": str(form.get("dst", "")), "port": str(form.get("dstport", "")),
            "target": str(form.get("target", "")), "local_port": str(form.get("localport", "")),
            "descr": str(form.get("descr", "")), "disabled": form.get("disabled") == "true"}


def _form_error(request: Request, form_id: str, message: str, values: dict[str, Any]) -> None:
    """Shown next to the form on the next page view, with what was typed (instead of a flash at the top)."""
    request.session["form_error"] = {"form": form_id, "message": message, "values": values}


@router.post("/devices/{device_id}/nat")
async def device_nat_add(device_id: str, request: Request, settings: Settings = Depends(get_settings),
                         user: User = Depends(operator), db: Session = Depends(get_db)):
    """Add one port forward to this firewall only (Configurations deploys them to many)."""
    device = _get_device(db, device_id)
    form = await request.form()
    try:
        rule = _port_forward_from_form(form)
    except PolicyError as exc:
        _form_error(request, "nat:add", str(exc), _nat_form_values(form))
        return redirect(f"/devices/{device_id}/configuration#nat-add")
    return _queue_change(request, db, settings, device, user, TaskType.nat_add, {"rule": rule},
                         f"add port forward {rule['destination']['port']} -> {rule['target']}:{rule['local_port']}", "#nat")


@router.post("/devices/{device_id}/nat/edit")
async def device_nat_edit(device_id: str, request: Request, settings: Settings = Depends(get_settings),
                          user: User = Depends(operator), db: Session = Depends(get_db)):
    """Change one port forward on this firewall, named by its fingerprint (as for removal)."""
    device = _get_device(db, device_id)
    form = await request.form()
    fingerprint = str(form.get("fingerprint", ""))
    if not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
        raise HTTPException(400, "Invalid port forward reference")
    try:
        rule = _port_forward_from_form(form)
    except PolicyError as exc:
        _form_error(request, f"nat:{fingerprint}", str(exc), _nat_form_values(form))
        return redirect(f"/devices/{device_id}/configuration?edit_nat={fingerprint}#nat-edit")
    return _queue_change(request, db, settings, device, user, TaskType.nat_edit,
                         {"fingerprint": fingerprint, "rule": rule},
                         f"change port forward {rule['descr'] or fingerprint} to "
                         f"{rule['destination']['port']} -> {rule['target']}:{rule['local_port']}", "#nat")


@router.post("/devices/{device_id}/nat/remove")
def device_nat_remove(device_id: str, request: Request, fingerprint: str = Form(...), descr: str = Form(""),
                      settings: Settings = Depends(get_settings), user: User = Depends(operator),
                      db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    if not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
        raise HTTPException(400, "Invalid port forward reference")
    return _queue_change(request, db, settings, device, user, TaskType.nat_remove,
                         {"fingerprint": fingerprint, "descr": descr[:200]},
                         f"remove port forward {descr or fingerprint}", "#nat")


@router.post("/devices/{device_id}/notifications")
def device_notifications(device_id: str, request: Request, smtp: str = Form(...),
                         settings: Settings = Depends(get_settings), user: User = Depends(operator),
                         db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    enabled = smtp == "on"
    return _queue_change(request, db, settings, device, user, TaskType.notifications, {"smtp": enabled},
                         f"turn {'on' if enabled else 'off'} pfSense email notifications", "#notifications")


DDNS_TEXT_RE = re.compile(r"^[^\x00-\x1f]{0,255}$")


def _ddns_from_form(form) -> dict[str, Any]:
    """One dynamic DNS client from the add or edit form on the Configuration page (raises PolicyError)."""
    def text(name: str, limit: int = 255) -> str:
        return str(form.get(name, "")).strip()[:limit]

    entry: dict[str, Any] = {
        "enable": form.get("enable") == "true",
        "type": text("type", 32), "interface": text("interface", 64), "host": text("host"),
        "domainname": text("domainname"), "username": text("username"), "password": str(form.get("password", "")),
        "zoneid": text("zoneid"), "ttl": text("ttl", 10), "mx": text("mx"), "updateurl": text("updateurl", 1024),
        "resultmatch": text("resultmatch", 1024), "descr": text("descr", 200),
        "wildcard": form.get("wildcard") == "true", "proxied": form.get("proxied") == "true",
        "verboselog": form.get("verboselog") == "true",
    }
    if not re.fullmatch(r"[a-z0-9._-]{1,32}", entry["type"], re.I):
        raise PolicyError("Choose a provider")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", entry["interface"]):
        raise PolicyError("Choose the interface whose address is published")
    custom = entry["type"].startswith("custom")
    if not custom and not re.fullmatch(r"[A-Za-z0-9*@_.-]{1,253}", entry["host"]):
        raise PolicyError("Enter the host name to update (for example home, or @ for the domain itself)")
    if entry["domainname"] and not re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", entry["domainname"]):
        raise PolicyError("The domain name is not valid")
    if entry["ttl"] and not entry["ttl"].isdigit():
        raise PolicyError("TTL is a number of seconds")
    if custom and not entry["updateurl"].startswith(("https://", "http://")):
        raise PolicyError("A custom provider needs its update URL (http:// or https://)")
    for key in ("username", "password", "zoneid", "mx", "resultmatch", "descr"):
        if not DDNS_TEXT_RE.match(str(entry[key])):
            raise PolicyError(f"{key} contains characters that are not allowed")
    return entry


def _ddns_label(entry: dict[str, Any]) -> str:
    host = entry.get("host", "")
    return f"{host}.{entry['domainname']}" if entry.get("domainname") and host not in ("", "@") else \
        (entry.get("domainname") or host)


@router.post("/devices/{device_id}/ddns")
async def device_ddns_add(device_id: str, request: Request, settings: Settings = Depends(get_settings),
                          user: User = Depends(operator), db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    try:
        entry = _ddns_from_form(await request.form())
    except PolicyError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/devices/{device_id}/configuration#ddns")
    return _queue_change(request, db, settings, device, user, TaskType.ddns_add, {"entry": entry},
                         f"add dynamic DNS {entry['type']} {_ddns_label(entry)}", "#ddns")


@router.post("/devices/{device_id}/ddns/edit")
async def device_ddns_edit(device_id: str, request: Request, settings: Settings = Depends(get_settings),
                           user: User = Depends(operator), db: Session = Depends(get_db)):
    """Change one dynamic DNS client, named by its fingerprint. An empty password keeps the current one."""
    device = _get_device(db, device_id)
    form = await request.form()
    fingerprint = str(form.get("fingerprint", ""))
    if not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
        raise HTTPException(400, "Invalid dynamic DNS reference")
    try:
        entry = _ddns_from_form(form)
    except PolicyError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/devices/{device_id}/configuration?edit_ddns={fingerprint}#ddns-edit")
    if not entry["password"]:
        del entry["password"]
    return _queue_change(request, db, settings, device, user, TaskType.ddns_edit,
                         {"fingerprint": fingerprint, "entry": entry},
                         f"change dynamic DNS {entry['type']} {_ddns_label(entry)}", "#ddns")


@router.post("/devices/{device_id}/ddns/remove")
def device_ddns_remove(device_id: str, request: Request, fingerprint: str = Form(...), descr: str = Form(""),
                       settings: Settings = Depends(get_settings), user: User = Depends(operator),
                       db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    if not re.fullmatch(r"[0-9a-f]{16}", fingerprint):
        raise HTTPException(400, "Invalid dynamic DNS reference")
    return _queue_change(request, db, settings, device, user, TaskType.ddns_remove,
                         {"fingerprint": fingerprint, "descr": descr[:200]},
                         f"remove dynamic DNS {descr or fingerprint}", "#ddns")


@router.post("/devices/{device_id}/update-branch")
def device_update_branch(device_id: str, request: Request, branch: str = Form(...),
                         settings: Settings = Depends(get_settings), user: User = Depends(operator),
                         db: Session = Depends(get_db)):
    """System > Update > Branch: one of the branches the firewall itself offers."""
    device = _get_device(db, device_id)
    offered = ((device.inventory or {}).get("update_branch") or {}).get("branches") or []
    match = next((b for b in offered if isinstance(b, dict) and b.get("name") == branch), None)
    if match is None:
        flash(request, "The firewall does not offer that update branch.", "error")
        return redirect(f"/devices/{device_id}/configuration#update-branch")
    return _queue_change(request, db, settings, device, user, TaskType.update_branch, {"branch": branch},
                         f"switch the update branch to {match.get('descr') or branch}", "#update-branch")


@router.post("/devices/{device_id}/boot-environments/remove")
def device_be_remove(device_id: str, request: Request, name: str = Form(...),
                     settings: Settings = Depends(get_settings), user: User = Depends(admin),
                     db: Session = Depends(get_db)):
    """Remove one ZFS boot environment (and its snapshot) to free space; never the running or next-boot one
    (checked here from the last check-in, and again on the firewall)."""
    device = _get_device(db, device_id)
    back = f"/devices/{device_id}/configuration#boot-environments"
    listed = (device.inventory or {}).get("boot_environments") or []
    be = next((b for b in listed if isinstance(b, dict) and b.get("name") == name), None)
    if be is None or not re.fullmatch(r"[A-Za-z0-9._:+-]{1,128}", name):
        flash(request, "The firewall did not report that boot environment.", "error")
        return redirect(back)
    if be.get("active") or be.get("next_boot"):
        flash(request, f"{name} is the boot environment the firewall runs or boots next; it cannot be removed.", "error")
        return redirect(back)
    try:
        queue_task(db, device, TaskType.be_destroy, {"name": name}, actor=user.username,
                   changes_enabled=settings.enable_firewall_changes)
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(back)
    audit(db, user.username, "task.be_destroy", target=device.id, detail=name, ip=_ip(request))
    db.commit()
    flash(request, f"Queued: remove boot environment {name}. The firewall runs it within seconds.", "success")
    return redirect(back)


def _alias_from_form(form) -> dict[str, Any]:
    """One alias from the add or edit form on the Configuration page (raises PolicyError)."""
    addresses, notes = parse_alias_entries(str(form.get("entries", "")))
    alias: dict[str, Any] = {"name": str(form.get("name", "")).strip(), "type": str(form.get("type", "host")),
                             "address": addresses, "descr": str(form.get("descr", "")).strip()[:200]}
    if any(notes):
        alias["detail"] = notes
    validate_alias(alias)
    return alias


@router.post("/devices/{device_id}/aliases")
async def device_alias_add(device_id: str, request: Request, settings: Settings = Depends(get_settings),
                           user: User = Depends(operator), db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    try:
        alias = _alias_from_form(await request.form())
    except PolicyError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/devices/{device_id}/configuration#aliases")
    return _queue_change(request, db, settings, device, user, TaskType.alias_add, {"alias": alias},
                         f"add alias {alias['name']}", "#aliases")


@router.post("/devices/{device_id}/aliases/edit")
async def device_alias_edit(device_id: str, request: Request, settings: Settings = Depends(get_settings),
                            user: User = Depends(operator), db: Session = Depends(get_db)):
    """Change an alias's type, entries and description; it keeps its name, which rules refer to."""
    device = _get_device(db, device_id)
    form = await request.form()
    try:
        alias = _alias_from_form(form)
    except PolicyError as exc:
        flash(request, str(exc), "error")
        name = str(form.get("name", ""))
        return redirect(f"/devices/{device_id}/configuration?edit_alias={name}#alias-edit"
                        if re.fullmatch(r"[A-Za-z0-9_]{1,31}", name) else f"/devices/{device_id}/configuration")
    return _queue_change(request, db, settings, device, user, TaskType.alias_edit, {"alias": alias},
                         f"change alias {alias['name']}", "#aliases")


@router.post("/devices/{device_id}/aliases/remove")
def device_alias_remove(device_id: str, request: Request, name: str = Form(...),
                        settings: Settings = Depends(get_settings), user: User = Depends(operator),
                        db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    if not re.fullmatch(r"[A-Za-z0-9_]{1,31}", name):
        raise HTTPException(400, "Invalid alias name")
    return _queue_change(request, db, settings, device, user, TaskType.alias_remove, {"name": name},
                         f"remove alias {name}", "#aliases")


@router.post("/devices/{device_id}/check-now")
def device_check_now(device_id: str, request: Request, next: str = Form(""), user: User = Depends(operator),
                     db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    back = local_path(next, f"/devices/{device_id}")
    try:
        _check_now(db, device, user.username)
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(back)
    audit(db, user.username, "device.check_now", target=device.id, ip=_ip(request))
    db.commit()
    flash(request, "Check requested. A connected firewall reports back within a few seconds; this page updates when it does.", "success")
    return redirect(back)


@router.get("/devices/{device_id}/network", response_class=HTMLResponse)
def device_network(device_id: str, request: Request, q: str = "", user: User = Depends(viewer),
                   db: Session = Depends(get_db)):
    """The firewall's ARP entries, DHCP leases and static mappings, as it last reported them."""
    device = _get_device(db, device_id)
    return render(request, "device_network.html", device=device, page_token=_device_page_token(db, device), q=q,
                  entries=neighbors_svc.device_entries(device, q), totals={k: len((device.neighbors or {}).get(k) or [])
                                                                         for k in neighbors_svc.KINDS})



@router.post("/devices/{device_id}/update-agent")
def device_update_agent(
    device_id: str,
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    package = latest_package(settings.data_dir / "downloads")
    if package is None:
        flash(request, "No agent package is available on this server.", "error")
        return redirect(f"/devices/{device_id}")
    try:
        task = _update_agent(db, device, user.username, package, settings.data_dir / "downloads")
    except TaskError as exc:
        flash(request, str(exc), "error")
        return redirect(f"/devices/{device_id}")
    db.flush()
    audit(db, user.username, "task.update_agent", target=device.id, detail=package["version"], ip=_ip(request))
    db.commit()
    flash(request, f"Queued task #{task.id}: update the agent to {package['version']}. "
          "The firewall installs it and checks in again with the new version.", "success")
    return redirect(f"/devices/{device_id}")


PROCESS_SORTS = {"cpu": "cpu", "mem": "rss_kb"}


@router.get("/devices/{device_id}/processes", response_class=HTMLResponse)
def device_processes(
    device_id: str, request: Request, sort: str = "cpu", user: User = Depends(viewer), db: Session = Depends(get_db)
):
    device = _get_device(db, device_id)
    snapshot = (device.inventory or {}).get("processes") or {}
    key = PROCESS_SORTS.get(sort, "cpu")
    rows = sorted(
        (p for p in snapshot.get("top") or [] if isinstance(p, dict)),
        key=lambda p: p.get(key) if isinstance(p.get(key), (int, float)) else 0,
        reverse=True,
    )
    return render(
        request,
        "processes.html",
        device=device,
        rows=rows,
        sort=sort if sort in PROCESS_SORTS else "cpu",
        taken_at=snapshot.get("taken_at"),
        total=snapshot.get("total"),
        metrics=(device.inventory or {}).get("metrics") or {},
    )


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
    name: str | None = Form(None),
    organization_id: str | None = Form(None),
    notes: str = Form(""),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    """The Notes card; name and customer are changed only when posted (the customer is set from the
    customer's page or the Firewalls list)."""
    device = _get_device(db, device_id)
    if name is not None:
        device.name = name.strip()[:128] or device.name
    if organization_id is not None:
        device.organization_id = int(organization_id) if organization_id.isdigit() else None
    device.notes = notes
    audit(db, user.username, "device.edited", target=device.id, ip=_ip(request))
    db.commit()
    flash(request, "Saved.", "success")
    return redirect(f"/devices/{device_id}/configuration#notes")


@router.post("/devices/{device_id}/status")
def device_set_status(
    device_id: str,
    request: Request,
    action: str = Form(...),
    next: str = Form(""),  # noqa: A002 - the form field
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
    if action == "approve":
        # Shown like the approval banner, under the navigation bar (base.html).
        flash(request, f"{device.name} has been approved. You should start receiving data shortly.", "approved")
    else:
        flash(request, f"Device {action}d.", "success")
    return redirect(local_path(next, f"/devices/{device_id}"))


@router.post("/devices/{device_id}/delete")
def device_delete(
    device_id: str,
    request: Request,
    next: str = Form(""),  # noqa: A002 - the form field
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
    back = local_path(next, "/devices")
    return redirect("/devices" if back.startswith(f"/devices/{device_id}") else back)


@router.post("/devices/{device_id}/policies")
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


@router.post("/devices/{device_id}/policies/{policy_id}/unassign")
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
    request: Request, show: str = "open", category: str = "", user: User = Depends(viewer),
    db: Session = Depends(get_db),
):
    stmt = select(Alert).order_by(Alert.opened_at.desc()).limit(500)
    if show == "open":
        stmt = stmt.where(Alert.resolved_at.is_(None))
    if category not in CATEGORIES:
        category = ""
    if category:
        stmt = stmt.where(category_filter(category))
    return render(request, "alerts.html", alerts=db.scalars(stmt).all(), show=show if show == "open" else "all",
                  category=category, category_names={k: v[0] for k, v in CATEGORIES.items()},
                  category_of=category_of)


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
    user: User = Depends(admin),  # the whole config.xml, secrets included
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


@router.get("/devices/{device_id}/config", response_class=HTMLResponse)
def device_config(
    device_id: str,
    request: Request,
    backup: int | None = None,
    secrets: int = 0,
    settings: Settings = Depends(get_settings),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    """The firewall's config.xml (its current one by default, or any stored backup), secrets hidden.
    Admins can show them; that is audited like a download."""
    device = _get_device(db, device_id)
    backups = db.scalars(
        select(Backup).where(Backup.device_id == device.id).order_by(Backup.created_at.desc())
    ).all()
    chosen = next((b for b in backups if b.id == backup), None) if backup else current_backup(db, device)
    text, error = "", ""
    show_secrets = bool(secrets) and user.role == Role.admin
    if chosen is not None:
        try:
            text = load_backup(settings, chosen).decode("utf-8", "replace")
        except (BackupError, OSError) as exc:
            error = str(exc)
        if not show_secrets:
            text = redact(text)
        else:
            audit(db, user.username, "backup.viewed_secrets", target=device.id, detail=str(chosen.id), ip=_ip(request))
            db.commit()
    return render(request, "device_config.html", device=device, backups=backups, chosen=chosen, xml=text,
                  error=error, show_secrets=show_secrets, current_sha=device.config_sha256)


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
        section="/keys",
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


# -------------------------------------------------------------------------- users


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    return render(request, "users.html", section="/users", users=db.scalars(select(User).order_by(User.username)).all())


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


def _target_user(db: Session, user_id: int) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    return target


@router.get("/users/{user_id}", response_class=HTMLResponse)
def user_page(user_id: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    target = _target_user(db, user_id)
    return render(request, "user.html", section="/users", target=target, email_ready=get_email_settings(db).configured)


@router.post("/users/{user_id}/flags")
def users_flags(
    user_id: int,
    request: Request,
    active: bool = Form(False),
    email_alerts: bool = Form(False),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    """The Active and Alerts checkboxes on the user list."""
    target = _target_user(db, user_id)
    if target.id == user.id and not active:
        flash(request, "You cannot deactivate your own account.", "error")
        return redirect("/users")
    if email_alerts and not target.email:
        flash(request, f"{target.username} has no email address for alerts.", "error")
        email_alerts = False
    target.active = active
    target.email_alerts = email_alerts
    audit(db, user.username, "user.updated", target=target.username,
          detail=f"active={active} alerts={email_alerts}", ip=_ip(request))
    db.commit()
    return redirect("/users")


@router.post("/users/{user_id}/password")
def users_set_password(
    user_id: int,
    request: Request,
    password: str = Form(""),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    target = _target_user(db, user_id)
    back = f"/users/{user_id}"
    if len(password) < 12:
        flash(request, "Passwords need at least 12 characters.", "error")
        return redirect(back)
    target.password_hash = hash_password(password)
    target.must_change_password = True
    audit(db, user.username, "user.password_set", target=target.username, ip=_ip(request))
    db.commit()
    flash(request, f"Temporary password set. {target.username} must choose a new one at the next sign-in.", "success")
    return redirect(back)


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
    target = _target_user(db, user_id)
    back = f"/users/{user_id}"
    if target.id == user.id and (Role(role) != Role.admin or not active):
        flash(request, "You cannot demote or deactivate your own account.", "error")
        return redirect(back)
    email = email.strip()
    if email and not valid_email(email):
        flash(request, "That is not a valid email address.", "error")
        return redirect(back)
    target.role = Role(role)
    target.active = active
    target.email = email
    target.email_alerts = email_alerts and bool(email)
    if password:
        if len(password) < 12:
            flash(request, "Passwords need at least 12 characters.", "error")
            return redirect(back)
        target.password_hash = hash_password(password)
        target.must_change_password = True
    audit(db, user.username, "user.updated", target=target.username, detail=f"role={role} active={active}", ip=_ip(request))
    db.commit()
    flash(request, "User updated.", "success")
    return redirect(back)


# -------------------------------------------------------------------------- audit


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    entries = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(500)).all()
    # Firewalls are logged by id (it never changes); show their current names.
    ids = {e.target for e in entries if e.target} | {
        e.actor.removeprefix("agent:") for e in entries if e.actor.startswith("agent:")
    }
    devices = {d.id: d.name for d in db.scalars(select(Device).where(Device.id.in_(ids)))} if ids else {}
    return render(request, "audit.html", entries=entries, devices=devices)
