"""Deleting a firewall. A firewall that was approved (it has history, backups and configuration) is deleted
only after the admin types its name and approves with MFA: their authenticator code, or, when they signed
in with single sign-on, a fresh sign-in to the provider (for example an Entra push). A pending firewall
that was never approved is rejected without MFA: it has nothing in the console yet."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import Device, DeviceStatus, Role, User
from ..security import RateLimiter
from ..services import mfa
from ..services import sso as sso_svc
from ..services.appsettings import effective_console_url
from ..services.backups import delete_backup_file
from .auth import flash, require, verify_csrf
from .routes import _get_device, _ip, local_path, redirect, render
from .terminal_routes import sso_provider

router = APIRouter(dependencies=[Depends(verify_csrf)])
admin = require(Role.admin)
delete_limiter = RateLimiter(limit=5, window_seconds=900)  # wrong codes per user


def _page(device_id: str) -> str:
    return f"/devices/{device_id}/delete"


def _name_matches(device: Device, typed: str) -> bool:
    return typed.strip().casefold() == (device.name or "").strip().casefold()


def _delete(request: Request, db: Session, settings: Settings, device: Device, user: User, approved_with: str,
            next_path: str = ""):
    for backup in device.backups:
        delete_backup_file(settings, backup)
    detail = device.name if not approved_with else f"{device.name} (approved with {approved_with})"
    audit(db, user.username, "device.deleted", target=device.id, detail=detail[:500], ip=_ip(request))
    db.delete(device)
    db.commit()
    flash(request, f"{device.name} and its backups were deleted. Its agent's token no longer works.", "success")
    back = local_path(next_path, "/devices")
    return redirect("/devices" if back.startswith(f"/devices/{device.id}") else back)


@router.get("/devices/{device_id}/delete", response_class=HTMLResponse)
def device_delete_page(device_id: str, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    provider = sso_provider(request, db)
    return render(request, "device_delete.html", device=device, sso=provider,
                  needs_totp=provider is None and not user.totp_enabled)


@router.post("/devices/{device_id}/delete")
def device_delete(
    device_id: str,
    request: Request,
    code: str = Form(""),
    confirm_name: str = Form(""),
    next: str = Form(""),  # noqa: A002 - the form field
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    if device.status == DeviceStatus.pending:  # rejecting an enrollment that was never approved
        return _delete(request, db, settings, device, user, "", next)
    back = _page(device_id)
    if not user.totp_enabled:
        flash(request, "Deleting a firewall needs an authenticator app or single sign-on approval.", "error")
        return redirect(back)
    if not _name_matches(device, confirm_name):
        flash(request, f"Type the firewall's name, {device.name}, to confirm.", "error")
        return redirect(back)
    key = f"delete:{user.id}"
    if delete_limiter.blocked(key):
        flash(request, "Too many wrong codes. Try again in 15 minutes.", "error")
        return redirect(back)
    if not mfa.verify_user_totp(user, code, settings.secret_key):
        delete_limiter.allow(key)
        audit(db, user.username, "device.delete_denied", target=device.id, detail="wrong authenticator code",
              ip=_ip(request))
        db.commit()
        flash(request, "That code is not valid. Enter the current code from your authenticator app.", "error")
        return redirect(back)
    return _delete(request, db, settings, device, user, "authenticator code")


@router.post("/devices/{device_id}/delete/sso")
def device_delete_sso(
    device_id: str,
    request: Request,
    confirm_name: str = Form(""),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    """Approve with the single sign-on provider: sign in to it again (it runs its MFA, e.g. an Entra push)."""
    from .sso_routes import step_up_redirect  # noqa: PLC0415 - sso_routes imports routes, as this module does

    device = _get_device(db, device_id)
    back = _page(device_id)
    provider = sso_provider(request, db)
    if provider is None:
        return redirect(back)
    if not _name_matches(device, confirm_name):
        flash(request, f"Type the firewall's name, {device.name}, to confirm.", "error")
        return redirect(back)
    purpose = {"kind": "delete", "user_id": user.id, "device_id": device.id}
    try:
        return step_up_redirect(provider, effective_console_url(db, settings), settings, purpose, device.id)
    except sso_svc.SsoError as exc:
        flash(request, f"{provider.name}: {exc}", "error")
        return redirect(back)


@router.get("/devices/{device_id}/delete/sso/{token}")
def device_delete_approved_sso(device_id: str, token: str, request: Request,
                               settings: Settings = Depends(get_settings), user: User = Depends(admin),
                               db: Session = Depends(get_db)):
    """Back from the provider (via sso_acs): delete the firewall if it approved this admin for it."""
    device = _get_device(db, device_id)
    back = _page(device_id)
    data = sso_svc.take_handoff(token)
    if data is None or data.get("kind") != "delete" or data.get("device_id") != device.id:
        flash(request, "That approval has expired or was already used. Approve again.", "error")
        return redirect(back)
    if data.get("error"):
        flash(request, data["error"], "error")
        return redirect(back)
    if data.get("user_id") != user.id:
        flash(request, "That approval is not for you.", "error")
        return redirect(back)
    return _delete(request, db, settings, device, user, data.get("approved_by", "single sign-on"))
