"""Two-factor sign-in pages: the second login step, setup on the Account page, the Security
settings page and the admin reset on the Users page. The logic lives in services/mfa.py."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import Role, User
from ..security import RateLimiter, verify_password
from ..services import mfa
from ..services.appsettings import (
    MFA_REQUIRED,
    SecuritySettings,
    get_email_settings,
    get_security_settings,
    save_security_settings,
)
from ..services.mailer import MailError, send_mail
from .auth import flash, require, verify_csrf
from .routes import _ip, complete_login, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
admin = require(Role.admin)
viewer = require(Role.viewer)

PENDING_TTL = 600  # seconds to finish the second step after the password
MAX_ATTEMPTS = 5  # wrong codes per sign-in before starting over
code_limiter = RateLimiter(limit=10, window_seconds=900)  # per user
email_limiter = RateLimiter(limit=5, window_seconds=900)  # emailed codes per user


def _email_ready(db: Session) -> bool:
    return get_email_settings(db).configured


def _send_code(db: Session, settings: Settings, user: User, code: str, purpose: str) -> None:
    text = (
        f"Your ComSense {purpose} code is: {code}\n\n"
        "It expires in 10 minutes. If you did not just try to sign in, change your password.\n"
    )
    send_mail(get_email_settings(db), settings.secret_key, [user.email], f"ComSense code: {code}", text)


# ----------------------------------------------------------- second login step


def begin_second_factor(request: Request, db: Session, user: User) -> bool:
    """After a correct password: start the second step if the user has a method. Returns True if so."""
    methods = mfa.user_methods(user, get_security_settings(db), _email_ready(db))
    if not methods:
        return False
    request.session["mfa"] = {
        "uid": user.id, "pwv": user.password_hash[-16:], "at": time.time(), "methods": methods, "tries": 0,
    }
    return True


def _pending(request: Request, db: Session) -> tuple[dict, User] | None:
    pending = request.session.get("mfa")
    if not isinstance(pending, dict) or time.time() - float(pending.get("at", 0)) > PENDING_TTL:
        request.session.pop("mfa", None)
        return None
    user = db.get(User, pending.get("uid"))
    if user is None or not user.active or user.password_hash[-16:] != pending.get("pwv"):
        request.session.pop("mfa", None)
        return None
    return pending, user


@router.get("/login/mfa", response_class=HTMLResponse)
def login_mfa_form(
    request: Request, settings: Settings = Depends(get_settings), db: Session = Depends(get_db)
):
    found = _pending(request, db)
    if found is None:
        flash(request, "Sign in again.", "warn")
        return redirect("/login")
    pending, user = found
    # Email is the only method: send the code straight away (once).
    if pending["methods"] == ["email"] and not pending.get("email_code"):
        _send_login_code(request, db, settings, user, pending)
    return render(
        request,
        "login_mfa.html",
        methods=pending["methods"],
        email_sent=bool(pending.get("email_code")),
        has_recovery=bool(user.recovery_codes) and "totp" in pending["methods"],
        email_hint=_mask_email(user.email),
    )


def _mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    return f"{name[:2]}…@{domain}" if domain else ""


def _send_login_code(request: Request, db: Session, settings: Settings, user: User, pending: dict) -> None:
    if not email_limiter.allow(f"login:{user.id}"):
        flash(request, "Too many codes requested. Wait a few minutes.", "error")
        return
    code, record = mfa.new_email_code(settings.secret_key, f"login:{user.id}")
    try:
        _send_code(db, settings, user, code, "sign-in")
    except MailError as exc:
        flash(request, f"The code could not be emailed: {exc}", "error")
        return
    pending["email_code"] = record
    request.session["mfa"] = pending
    flash(request, f"A code was emailed to {_mask_email(user.email)}.", "info")


@router.post("/login/mfa/email")
def login_mfa_email(request: Request, settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    found = _pending(request, db)
    if found is None:
        return redirect("/login")
    pending, user = found
    if "email" in pending["methods"]:
        _send_login_code(request, db, settings, user, pending)
    return redirect("/login/mfa")


@router.post("/login/mfa")
def login_mfa(
    request: Request,
    code: str = Form(""),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    found = _pending(request, db)
    if found is None:
        flash(request, "Sign in again.", "warn")
        return redirect("/login")
    pending, user = found
    if not code_limiter.allow(f"login:{user.id}"):
        flash(request, "Too many attempts. Wait a few minutes and sign in again.", "error")
        request.session.pop("mfa", None)
        return redirect("/login")

    method = ""
    if "totp" in pending["methods"] and mfa.verify_user_totp(user, code, settings.secret_key):
        method = "totp"
    elif "email" in pending["methods"] and mfa.check_email_code(pending.get("email_code"), code, settings.secret_key,
                                                                           f"login:{user.id}"):
        method = "email"
    elif "totp" in pending["methods"] and mfa.use_recovery_code(user, code):
        method = "recovery"
        flash(request, f"Signed in with a recovery code; {len(user.recovery_codes or [])} left. "
              "Create new ones on your Account page if you are running low.", "warn")
    if method:
        return complete_login(request, db, user, method)

    pending["tries"] = int(pending.get("tries", 0)) + 1
    audit(db, user.username, "login.mfa_failed", ip=_ip(request))
    db.commit()
    if pending["tries"] >= MAX_ATTEMPTS:
        request.session.pop("mfa", None)
        flash(request, "Too many wrong codes. Sign in again.", "error")
        return redirect("/login")
    request.session["mfa"] = pending
    flash(request, "That code is not valid.", "error")
    return redirect("/login/mfa")


# --------------------------------------------------------------- account page


@router.get("/account", response_class=HTMLResponse)
def account(request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    sec = get_security_settings(db)
    email_ready = _email_ready(db)
    setup_secret = request.session.get("totp_setup")
    return render(
        request,
        "account.html",
        sec=sec,
        mfa_allowed=mfa.allowed_methods(sec, email_ready),
        mfa_active=mfa.user_methods(user, sec, email_ready),
        mfa_required=mfa.mfa_required(user, sec) and sec.mfa_required != "off",
        email_ready=email_ready,
        totp_setup=setup_secret,
        totp_qr=mfa.qr_svg(mfa.provisioning_uri(setup_secret, user.username)) if setup_secret else "",
        email_setup=bool(request.session.get("email_setup")),
        new_codes=request.session.pop("new_recovery_codes", None),
        recovery_left=len(user.recovery_codes or []),
    )


def _check_password(request: Request, user: User, password: str) -> bool:
    if verify_password(password, user.password_hash):
        return True
    flash(request, "Your password is not correct.", "error")
    return False


def _last_method_required(db: Session, user: User, method: str) -> bool:
    sec = get_security_settings(db)
    others = [m for m in mfa.user_methods(user, sec, _email_ready(db)) if m != method]
    return mfa.mfa_required(user, sec) and sec.mfa_required != "off" and not others


@router.post("/account/mfa/totp/start")
def totp_start(request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    if not get_security_settings(db).allow_totp:
        raise HTTPException(403, "Authenticator apps are turned off in Settings > Security")
    if user.totp_enabled:
        # Replacing it would also hand over the terminal's approval codes; turn it off first (password).
        flash(request, "An authenticator app is already set up. Turn it off first to set up another.", "error")
        return redirect("/account#mfa")
    request.session["totp_setup"] = mfa.new_totp_secret()
    return redirect("/account#mfa")


@router.post("/account/mfa/totp/cancel")
def totp_cancel(request: Request, user: User = Depends(viewer)):
    request.session.pop("totp_setup", None)
    return redirect("/account#mfa")


@router.post("/account/mfa/totp/confirm")
def totp_confirm(
    request: Request,
    code: str = Form(""),
    password: str = Form(""),
    settings: Settings = Depends(get_settings),
    user: User = Depends(viewer),
    db: Session = Depends(get_db),
):
    secret = request.session.get("totp_setup")
    if not secret or user.totp_enabled:
        return redirect("/account#mfa")
    # A borrowed session must not be enough to enroll (the codes also approve root terminals). People
    # who sign in with single sign-on have no ComSense password; their provider vouched for them.
    if request.session.get("auth") != "sso" and not _check_password(request, user, password):
        return redirect("/account#mfa")
    step = mfa.match_totp(secret, code)
    if step is None:
        flash(request, "That code does not match. Check the time on your phone and try the current code.", "error")
        return redirect("/account#mfa")
    mfa.enable_totp(user, secret, step, settings.secret_key)
    request.session.pop("totp_setup", None)
    request.session["new_recovery_codes"] = mfa.new_recovery_codes(user)
    audit(db, user.username, "mfa.totp_enabled", target=user.username, ip=_ip(request))
    db.commit()
    flash(request, "Authenticator app turned on. Save your recovery codes now.", "success")
    return redirect("/account#mfa")


@router.post("/account/mfa/totp/disable")
def totp_disable(
    request: Request, password: str = Form(""), user: User = Depends(viewer), db: Session = Depends(get_db)
):
    if not _check_password(request, user, password):
        return redirect("/account#mfa")
    if _last_method_required(db, user, "totp"):
        flash(request, "Two-factor sign-in is required for your account; turn on another method first.", "error")
        return redirect("/account#mfa")
    user.totp_secret, user.totp_enabled, user.totp_last_step, user.recovery_codes = "", False, 0, []
    audit(db, user.username, "mfa.totp_disabled", target=user.username, ip=_ip(request))
    db.commit()
    flash(request, "Authenticator app turned off.", "success")
    return redirect("/account#mfa")


@router.post("/account/mfa/recovery")
def recovery_regenerate(
    request: Request, password: str = Form(""), user: User = Depends(viewer), db: Session = Depends(get_db)
):
    if not user.totp_enabled or not _check_password(request, user, password):
        return redirect("/account#mfa")
    request.session["new_recovery_codes"] = mfa.new_recovery_codes(user)
    audit(db, user.username, "mfa.recovery_codes_regenerated", target=user.username, ip=_ip(request))
    db.commit()
    flash(request, "New recovery codes created; the old ones no longer work.", "success")
    return redirect("/account#mfa")


@router.post("/account/mfa/email/start")
def email_start(
    request: Request, settings: Settings = Depends(get_settings), user: User = Depends(viewer),
    db: Session = Depends(get_db),
):
    if not (get_security_settings(db).allow_email and _email_ready(db)):
        raise HTTPException(403, "Email codes are not available")
    if not user.email:
        flash(request, "Add your email address first.", "error")
        return redirect("/account#mfa")
    if not email_limiter.allow(f"setup:{user.id}"):
        flash(request, "Too many codes requested. Wait a few minutes.", "error")
        return redirect("/account#mfa")
    code, record = mfa.new_email_code(settings.secret_key, f"setup:{user.id}")
    try:
        _send_code(db, settings, user, code, "verification")
    except MailError as exc:
        flash(request, f"The code could not be emailed: {exc}", "error")
        return redirect("/account#mfa")
    request.session["email_setup"] = record
    flash(request, f"A code was emailed to {user.email}.", "info")
    return redirect("/account#mfa")


@router.post("/account/mfa/email/confirm")
def email_confirm(
    request: Request, code: str = Form(""), settings: Settings = Depends(get_settings),
    user: User = Depends(viewer), db: Session = Depends(get_db)
):
    if not code_limiter.allow(f"setup:{user.id}"):
        flash(request, "Too many attempts. Wait a few minutes.", "error")
        return redirect("/account#mfa")
    if not mfa.check_email_code(request.session.get("email_setup"), code, settings.secret_key, f"setup:{user.id}"):
        flash(request, "That code is not valid or has expired.", "error")
        return redirect("/account#mfa")
    request.session.pop("email_setup", None)
    user.mfa_email_enabled = True
    audit(db, user.username, "mfa.email_enabled", target=user.username, ip=_ip(request))
    db.commit()
    flash(request, "Email codes turned on.", "success")
    return redirect("/account#mfa")


@router.post("/account/mfa/email/disable")
def email_disable(
    request: Request, password: str = Form(""), user: User = Depends(viewer), db: Session = Depends(get_db)
):
    if not _check_password(request, user, password):
        return redirect("/account#mfa")
    if _last_method_required(db, user, "email"):
        flash(request, "Two-factor sign-in is required for your account; turn on another method first.", "error")
        return redirect("/account#mfa")
    user.mfa_email_enabled = False
    audit(db, user.username, "mfa.email_disabled", target=user.username, ip=_ip(request))
    db.commit()
    flash(request, "Email codes turned off.", "success")
    return redirect("/account#mfa")


# ------------------------------------------------------- admin: settings, reset


@router.get("/settings/security", response_class=HTMLResponse)
def settings_security_page(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    from .account_routes import _settings_page  # noqa: PLC0415 - shared settings layout

    return _settings_page(
        request, "/settings/security", sec=get_security_settings(db), email_ready=_email_ready(db),
        mfa_levels=MFA_REQUIRED,
    )


@router.post("/settings/security")
def settings_security(
    request: Request,
    mfa_required: str = Form("off"),
    allow_totp: bool = Form(False),
    allow_email: bool = Form(False),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    if mfa_required not in MFA_REQUIRED:
        raise HTTPException(400, "Invalid choice")
    if mfa_required != "off" and not (allow_totp or allow_email):
        flash(request, "Allow at least one method when two-factor sign-in is required.", "error")
        return redirect("/settings/security")
    sec = SecuritySettings(mfa_required=mfa_required, allow_totp=allow_totp, allow_email=allow_email)
    save_security_settings(db, sec, user.username)
    audit(db, user.username, "settings.security_updated",
          detail=f"mfa_required={mfa_required} totp={allow_totp} email={allow_email}", ip=_ip(request))
    db.commit()
    msg = "Security settings saved."
    if mfa.mfa_required(user, sec) and not mfa.user_methods(user, sec, _email_ready(db)):
        msg += " You are now required to set up two-factor sign-in yourself."
    flash(request, msg, "success")
    return redirect("/settings/security")


@router.post("/users/{user_id}/mfa-reset")
def users_mfa_reset(user_id: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    mfa.clear_mfa(target)
    audit(db, user.username, "mfa.reset", target=target.username, ip=_ip(request))
    db.commit()
    flash(request, f"Two-factor sign-in reset for {target.username}. They can set it up again after signing in.", "success")
    return redirect(f"/users/{user_id}")
