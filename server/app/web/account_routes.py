"""Settings page (email, alert notifications), password reset by email and user email preferences."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db, session_factory
from ..models import Role, User, utcnow
from ..security import RateLimiter, hash_password
from ..services.appsettings import (
    SEVERITIES,
    SMTP_SECURITY,
    AgentNetworkSettings,
    effective_console_url,
    encrypt_secret,
    get_agent_network_settings,
    get_alert_email_settings,
    get_email_settings,
    get_site_settings,
    normalize_agent_url,
    normalize_console_url,
    save_agent_network_settings,
    save_alert_email_settings,
    save_email_settings,
    save_site_settings,
)
from ..services.mailer import MailError, send_mail
from ..services.notifications import create_reset_token, find_reset_token, send_reset_email
from .auth import flash, require, verify_csrf
from .routes import _ip, redirect, render, valid_email

router = APIRouter(dependencies=[Depends(verify_csrf)])
admin = require(Role.admin)
viewer = require(Role.viewer)
forgot_limiter = RateLimiter(limit=5, window_seconds=900)

# Pages the settings forms may return to: the Settings page or a setup wizard step.
RETURN_PAGES = {"/settings", "/setup", "/setup/email", "/setup/agent"}


def _page(value: str, default: str = "/settings") -> str:
    return value if value in RETURN_PAGES else default

def _send_reset_in_background(settings: Settings, user_id: int, token: str, by_admin: bool) -> None:
    # Runs after the response, so the forgot-password page answers in constant time.
    with session_factory()() as db:
        user = db.get(User, user_id)
        if user is None:
            return
        try:
            send_reset_email(db, settings, user, token, requested_by_admin=by_admin)
        except MailError as exc:
            audit(db, "system", "password_reset.email_failed", target=user.username, detail=str(exc))
            db.commit()


# ------------------------------------------------------------------- settings


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    alert_cfg = get_alert_email_settings(db)
    recipients = db.scalar(
        select(func.count()).select_from(User).where(
            User.active.is_(True), User.email_alerts.is_(True), User.email != ""
        )
    )
    return render(
        request,
        "settings.html",
        email=get_email_settings(db),
        alerts=alert_cfg,
        securities=SMTP_SECURITY,
        severities=SEVERITIES,
        opted_in_users=recipients,
        agent_network=get_agent_network_settings(db),
        default_agent_url=settings.agent_url,
        site=get_site_settings(db),
        default_console_url=settings.public_url.rstrip("/"),
    )


@router.post("/settings/email")
def settings_email(
    request: Request,
    enabled: bool = Form(False),
    host: str = Form(""),
    port: int = Form(587),
    security: str = Form("starttls"),
    username: str = Form(""),
    password: str = Form(""),
    clear_password: bool = Form(False),
    from_address: str = Form(""),
    from_name: str = Form(""),
    back: str = Form("/settings"),
    next: str = Form("/settings"),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    cfg = get_email_settings(db)
    host, from_address = host.strip(), from_address.strip()
    if enabled and (not host or not valid_email(from_address)):
        flash(request, "To turn email on, enter the SMTP server and a valid From address.", "error")
        return redirect(_page(back))
    if security not in SMTP_SECURITY or not 1 <= port <= 65535:
        raise HTTPException(400, "Invalid SMTP security or port")
    cfg.enabled = enabled
    cfg.host = host[:255]
    cfg.port = port
    cfg.security = security
    cfg.username = username.strip()[:255]
    cfg.from_address = from_address[:255]
    cfg.from_name = from_name.strip()[:128]
    if clear_password:
        cfg.password_encrypted = ""
    elif password:
        cfg.password_encrypted = encrypt_secret(settings.secret_key, password)
    save_email_settings(db, cfg, user.username)
    audit(db, user.username, "settings.email_updated", detail=f"enabled={enabled} host={cfg.host}", ip=_ip(request))
    db.commit()
    flash(request, "Email settings saved.", "success")
    return redirect(_page(next))


@router.post("/settings/email/test")
def settings_email_test(
    request: Request,
    to: str = Form(""),
    back: str = Form("/settings"),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    to = to.strip() or user.email
    if not valid_email(to):
        flash(request, "Enter an address to send the test email to.", "error")
        return redirect(_page(back))
    try:
        send_mail(
            get_email_settings(db),
            settings.secret_key,
            [to],
            "ComSense test email",
            f"This is a test email from ComSense Firewall Manager at {effective_console_url(db, settings)}.\n"
            "If you received it, outgoing email is working.\n",
        )
    except MailError as exc:
        flash(request, f"Sending failed: {exc}", "error")
    else:
        flash(request, f"Test email sent to {to}.", "success")
    audit(db, user.username, "settings.email_test", target=to, ip=_ip(request))
    db.commit()
    return redirect(_page(back))


@router.post("/settings/alerts")
def settings_alerts(
    request: Request,
    enabled: bool = Form(False),
    min_severity: str = Form("warning"),
    notify_resolved: bool = Form(False),
    extra_recipients: str = Form(""),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    if min_severity not in SEVERITIES:
        raise HTTPException(400, "Invalid severity")
    extras = [e for e in re.split(r"[\s,;]+", extra_recipients.strip()) if e]
    bad = [e for e in extras if not valid_email(e)]
    if bad:
        flash(request, f"Not a valid email address: {', '.join(bad)}", "error")
        return redirect("/settings")
    cfg = get_alert_email_settings(db)
    if enabled and not cfg.enabled:
        # Only alerts opened from now on are emailed, not the existing backlog.
        cfg.enabled_since = utcnow().isoformat()
    cfg.enabled = enabled
    cfg.min_severity = min_severity
    cfg.notify_resolved = notify_resolved
    cfg.extra_recipients = extras
    save_alert_email_settings(db, cfg, user.username)
    audit(db, user.username, "settings.alerts_updated", detail=f"enabled={enabled} severity={min_severity}", ip=_ip(request))
    db.commit()
    flash(request, "Alert email settings saved.", "success")
    return redirect("/settings")


@router.post("/settings/agent-network")
def settings_agent_network(
    request: Request,
    console_url: str = Form(""),
    agent_url: str = Form(""),
    trusted_proxies: str = Form(""),
    back: str = Form("/settings"),
    next: str = Form("/settings"),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    try:
        console = normalize_console_url(console_url)
    except ValueError as exc:
        flash(request, f"Console address: {exc}", "error")
        return redirect(_page(back))
    try:
        url = normalize_agent_url(agent_url, urlsplit(settings.agent_url).port or settings.agent_port)
    except ValueError as exc:
        flash(request, f"Agent address: {exc}", "error")
        return redirect(_page(back))
    entries = [e for e in re.split(r"[\s,;]+", trusted_proxies.strip()) if e]
    networks = []
    for entry in entries:
        try:
            networks.append(str(ipaddress.ip_network(entry, strict=False)))
        except ValueError:
            flash(request, f"Not an IP address or network: {entry}", "error")
            return redirect(_page(back))
    site = get_site_settings(db)
    site.console_url = console
    save_site_settings(db, site, user.username)
    save_agent_network_settings(
        db, AgentNetworkSettings(trusted_proxies=networks, agent_url=url), user.username
    )
    audit(
        db,
        user.username,
        "settings.addresses_updated",
        detail=f"console={console or 'default'} agent={url or 'default'} trusted={', '.join(networks) or 'none'}",
        ip=_ip(request),
    )
    db.commit()
    flash(request, "Addresses saved. Trusted proxies take effect within 15 seconds.", "success")
    return redirect(_page(next))


# ---------------------------------------------------------- password resets


@router.get("/forgot", response_class=HTMLResponse)
def forgot_form(request: Request, db: Session = Depends(get_db)):
    return render(request, "forgot.html", email_ready=get_email_settings(db).configured)


@router.post("/forgot")
def forgot_submit(
    request: Request,
    background: BackgroundTasks,
    identifier: str = Form(...),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    ip = _ip(request)
    identifier = identifier.strip()
    if forgot_limiter.allow(ip) and identifier and get_email_settings(db).configured:
        target = db.scalar(
            select(User).where(
                User.active.is_(True),
                User.email != "",
                or_(User.username == identifier, func.lower(User.email) == identifier.lower()),
            )
        )
        if target is not None:
            token = create_reset_token(db, target, ip)
            audit(db, target.username, "password_reset.requested", target=target.username, ip=ip)
            db.commit()
            background.add_task(_send_reset_in_background, settings, target.id, token, False)
    # Same answer whether or not the account exists.
    flash(request, "If that account exists and has an email address, a reset link is on its way. It expires in 1 hour.", "success")
    return redirect("/login")


@router.get("/reset/{token}", response_class=HTMLResponse)
def reset_form(token: str, request: Request, db: Session = Depends(get_db)):
    row = find_reset_token(db, token)
    if row is None:
        flash(request, "That reset link is invalid, already used or expired. Request a new one.", "error")
        return redirect("/forgot")
    return render(request, "reset.html", token=token, username=db.get(User, row.user_id).username)


@router.post("/reset/{token}")
def reset_submit(
    token: str,
    request: Request,
    new: str = Form(...),
    confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    row = find_reset_token(db, token)
    if row is None:
        flash(request, "That reset link is invalid, already used or expired. Request a new one.", "error")
        return redirect("/forgot")
    if new != confirm:
        flash(request, "The passwords do not match.", "error")
        return redirect(f"/reset/{token}")
    if len(new) < 12:
        flash(request, "Use at least 12 characters.", "error")
        return redirect(f"/reset/{token}")
    user = db.get(User, row.user_id)
    user.password_hash = hash_password(new)  # also signs out every existing session
    user.must_change_password = False
    row.used_at = utcnow()
    audit(db, user.username, "password_reset.completed", target=user.username, ip=_ip(request))
    db.commit()
    request.session.clear()
    flash(request, "Password changed. Sign in with your new password.", "success")
    return redirect("/login")


# ------------------------------------------------------------ user email


@router.post("/users/{user_id}/send-reset")
def users_send_reset(
    user_id: int,
    request: Request,
    background: BackgroundTasks,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    if not target.email:
        flash(request, f"{target.username} has no email address.", "error")
    elif not get_email_settings(db).configured:
        flash(request, "Set up email under Settings first.", "error")
    else:
        token = create_reset_token(db, target, _ip(request))
        audit(db, user.username, "password_reset.sent", target=target.username, ip=_ip(request))
        db.commit()
        background.add_task(_send_reset_in_background, settings, target.id, token, True)
        flash(request, f"Password reset link sent to {target.email}.", "success")
    return redirect("/users")


@router.post("/account/profile")
def account_profile(
    request: Request,
    email: str = Form(""),
    email_alerts: bool = Form(False),
    user: User = Depends(viewer),
    db: Session = Depends(get_db),
):
    email = email.strip()
    if email and not valid_email(email):
        flash(request, "That is not a valid email address.", "error")
        return redirect("/account")
    user.email = email
    user.email_alerts = email_alerts and bool(email)
    audit(db, user.username, "user.profile_updated", target=user.username, ip=_ip(request))
    db.commit()
    flash(request, "Profile saved.", "success")
    return redirect("/account")
