"""Single sign-on: SAML sign-in endpoints and Settings > Single sign-on. The SAML handling itself is in
services/sso.py."""
from __future__ import annotations

import secrets
from html import escape

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import Role, SsoProvider, User
from ..security import hash_password
from ..services import sso
from ..services.appsettings import effective_console_url
from .auth import flash, require, verify_csrf
from .routes import _ip, complete_login, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
# Called by the browser coming back from the provider (a cross-site form post): no CSRF token.
public = APIRouter()
admin = require(Role.admin)


def _provider(db: Session, provider_id: int, enabled_only: bool = False) -> SsoProvider:
    provider = db.get(SsoProvider, provider_id)
    if provider is None or (enabled_only and not provider.enabled):
        raise HTTPException(404, "Sign-in provider not found")
    return provider


def enabled_providers(db: Session) -> list[SsoProvider]:
    return list(db.scalars(select(SsoProvider).where(SsoProvider.enabled.is_(True)).order_by(SsoProvider.name)))


# ------------------------------------------------------------------ sign-in

@public.get("/sso/{provider_id:int}/login")
def sso_login(provider_id: int, request: Request, settings: Settings = Depends(get_settings),
              db: Session = Depends(get_db)):
    provider = _provider(db, provider_id, enabled_only=True)
    try:
        url, nonce = sso.login_redirect(provider, effective_console_url(db, settings))
    except sso.SsoError as exc:
        flash(request, f"{provider.name}: {exc}", "error")
        return redirect("/login")
    response = RedirectResponse(url, status_code=303)
    # Sent back with the provider's cross-site POST, which the SameSite=Strict session cookie is not.
    response.set_cookie(sso.NONCE_COOKIE, nonce, max_age=sso.REQUEST_TTL, path="/sso/", httponly=True,
                        secure=settings.secure_cookies, samesite="none" if settings.secure_cookies else "lax")
    return response


def _continue(target: str, request: Request) -> HTMLResponse:
    """A same-site step back into the console. After the provider's cross-site POST, a redirect would
    still count as cross-site, and the browser would not send the SameSite=Strict session cookie."""
    target = escape(target, quote=True)
    response = HTMLResponse(
        f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={target}">'
        f'<title>Signing in</title><p>Signing in&hellip; <a href="{target}">Continue</a></p>'
    )
    response.delete_cookie(sso.NONCE_COOKIE, path="/sso/")
    return response


@public.post("/sso/{provider_id:int}/acs")
def sso_acs(
    provider_id: int,
    request: Request,
    SAMLResponse: str = Form(""),  # noqa: N803 - the SAML field name
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    provider = _provider(db, provider_id, enabled_only=True)
    try:
        identity = sso.validate_response(SAMLResponse, provider, effective_console_url(db, settings),
                                         request.cookies.get(sso.NONCE_COOKIE))
    except sso.SsoError as exc:
        audit(db, "system", "login.sso_failed", target=provider.name, detail=str(exc)[:500], ip=_ip(request))
        db.commit()
        flash(request, f"Sign-in with {provider.name} failed: {exc}", "error")
        return _continue("/login", request)

    user = db.scalar(select(User).where(or_(func.lower(User.email) == identity.email,
                                            func.lower(User.username) == identity.email)))
    if user is None and provider.auto_create:
        user = User(username=identity.email[:64], email=identity.email, role=provider.default_role,
                    password_hash=hash_password(secrets.token_urlsafe(32)))
        db.add(user)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            user = None
        else:
            audit(db, "system", "user.created", target=user.username,
                  detail=f"{user.role.value}, first sign-in with {provider.name}", ip=_ip(request))
    if user is None or not user.active:
        reason = "is not a ComSense user" if user is None else "is disabled"
        audit(db, "system", "login.sso_failed", target=provider.name, detail=f"{identity.email} {reason}",
              ip=_ip(request))
        db.commit()
        flash(request, f"{identity.email} {reason}. Ask an admin to add you with this email address.", "error")
        return _continue("/login", request)

    if user.must_change_password:
        user.must_change_password = False  # signs in with the provider, not a password
    destination = complete_login(request, db, user, method=f"sso:{provider.name}").headers["location"]
    request.session["auth"] = "sso"
    return _continue(destination, request)


@public.get("/sso/{provider_id:int}/metadata")
def sso_metadata(provider_id: int, settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    provider = _provider(db, provider_id)
    return Response(sso.sp_metadata(effective_console_url(db, settings), provider), media_type="application/xml")


# ------------------------------------------------------------------ settings

def _sso_page(request: Request, db: Session, settings: Settings, provider: SsoProvider | None = None, **ctx):
    console = effective_console_url(db, settings)
    providers = db.scalars(select(SsoProvider).order_by(SsoProvider.name)).all()
    return render(request, "settings_sso.html", section="/settings/sso", providers=providers, provider=provider,
                  kinds=sso.KINDS, roles=list(Role), console=console,
                  entity_id=(lambda p: sso.sp_entity_id(console, p)), acs=(lambda p: sso.acs_url(console, p)),
                  certs=sso.cert_summary(provider.idp_cert) if provider else [], **ctx)


@router.get("/settings/sso", response_class=HTMLResponse)
def sso_settings(request: Request, settings: Settings = Depends(get_settings), user: User = Depends(admin),
                 db: Session = Depends(get_db)):
    return _sso_page(request, db, settings)


@router.get("/settings/sso/{provider_id:int}", response_class=HTMLResponse)
def sso_provider_page(provider_id: int, request: Request, settings: Settings = Depends(get_settings),
                      user: User = Depends(admin), db: Session = Depends(get_db)):
    return _sso_page(request, db, settings, provider=_provider(db, provider_id))


def _apply_form(provider: SsoProvider, form) -> None:
    metadata = str(form.get("metadata", "")).strip()
    if metadata:
        found = sso.parse_idp_metadata(metadata)
        provider.idp_entity_id, provider.idp_sso_url, provider.idp_cert = found["entity_id"], found["sso_url"], found["cert"]
    else:
        provider.idp_entity_id = str(form.get("idp_entity_id", provider.idp_entity_id)).strip()
        provider.idp_sso_url = str(form.get("idp_sso_url", provider.idp_sso_url)).strip()
        cert = str(form.get("idp_cert", "")).strip()
        if cert:
            provider.idp_cert = cert
    if provider.idp_sso_url and not provider.idp_sso_url.startswith("https://"):
        raise sso.SsoError("The provider's sign-in URL must start with https://")
    if provider.idp_cert and not any(c["expires"] for c in sso.cert_summary(provider.idp_cert)):
        raise sso.SsoError("The signing certificate could not be read; paste it in PEM format")
    provider.name = str(form.get("name", "")).strip()[:64] or sso.KINDS[provider.kind]["label"]
    provider.email_attribute = str(form.get("email_attribute", "")).strip()[:255]
    provider.enabled = form.get("enabled") == "true"
    provider.auto_create = form.get("auto_create") == "true"
    role = str(form.get("default_role", "viewer"))
    provider.default_role = Role(role) if role in Role.__members__ else Role.viewer


@router.post("/settings/sso")
async def sso_provider_create(request: Request, settings: Settings = Depends(get_settings),
                              user: User = Depends(admin), db: Session = Depends(get_db)):
    form = await request.form()
    kind = str(form.get("kind", "saml"))
    if kind not in sso.KINDS:
        raise HTTPException(400, "Unknown provider type")
    provider = SsoProvider(kind=kind, name=sso.KINDS[kind]["label"], email_attribute=sso.KINDS[kind]["email_attribute"],
                           enabled=False)
    db.add(provider)
    db.flush()
    audit(db, user.username, "sso.created", target=provider.name, ip=_ip(request))
    db.commit()
    flash(request, f"Added {provider.name}. Register ComSense at the provider with the values below, then paste "
          "the provider's metadata and turn it on.", "success")
    return redirect(f"/settings/sso/{provider.id}")


@router.post("/settings/sso/{provider_id:int}")
async def sso_provider_update(provider_id: int, request: Request, user: User = Depends(admin),
                              db: Session = Depends(get_db)):
    provider = _provider(db, provider_id)
    form = await request.form()
    try:
        _apply_form(provider, form)
        if provider.enabled and not (provider.idp_entity_id and provider.idp_sso_url and provider.idp_cert):
            raise sso.SsoError("Paste the provider's metadata (or its entity ID, sign-in URL and certificate) "
                               "before turning it on")
    except sso.SsoError as exc:
        db.rollback()
        flash(request, str(exc), "error")
        return redirect(f"/settings/sso/{provider_id}")
    audit(db, user.username, "sso.updated", target=provider.name,
          detail=f"enabled={provider.enabled} auto_create={provider.auto_create} role={provider.default_role.value}",
          ip=_ip(request))
    db.commit()
    flash(request, "Saved." + (" The sign-in page now offers it." if provider.enabled else ""), "success")
    return redirect(f"/settings/sso/{provider_id}")


@router.post("/settings/sso/{provider_id:int}/delete")
def sso_provider_delete(provider_id: int, request: Request, user: User = Depends(admin),
                        db: Session = Depends(get_db)):
    provider = _provider(db, provider_id)
    audit(db, user.username, "sso.deleted", target=provider.name, ip=_ip(request))
    db.delete(provider)
    db.commit()
    flash(request, "Sign-in provider removed.", "success")
    return redirect("/settings/sso")
