"""First-run setup wizard: addresses, outgoing email, then the first firewall.

Admins land here after replacing the temporary password, and from the
dashboard while setup is unfinished and no firewall is enrolled. Each step
saves through the same endpoints as the Settings page; this module only adds
the pages, the first enrollment code and the "finished" marker.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..enrollment import make_code
from ..models import Organization, Role, User, utcnow
from ..services.agentpkg import latest_package
from ..services.appsettings import (
    SMTP_SECURITY,
    effective_agent_url,
    effective_console_url,
    get_agent_network_settings,
    get_email_settings,
    get_site_settings,
    save_site_settings,
)
from ..tls import ensure_agent_tls
from .auth import flash, require, verify_csrf
from .routes import _ip, create_enrollment_key, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
admin = require(Role.admin)

STEPS = [("/setup", "Addresses"), ("/setup/email", "Email"), ("/setup/agent", "First firewall")]


def _render(request: Request, step: int, **ctx):
    return render(request, "setup.html", step=step, steps=STEPS, securities=SMTP_SECURITY, **ctx)


@router.get("/setup", response_class=HTMLResponse)
def setup_addresses(
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    return _render(
        request,
        1,
        site=get_site_settings(db),
        agent_network=get_agent_network_settings(db),
        default_console_url=settings.public_url.rstrip("/"),
        default_agent_url=settings.agent_url,
    )


@router.get("/setup/email", response_class=HTMLResponse)
def setup_email(request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    return _render(request, 2, email=get_email_settings(db))


@router.get("/setup/agent", response_class=HTMLResponse)
def setup_agent(
    request: Request,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    tls = ensure_agent_tls(settings)
    pin = tls.pin if tls.self_signed else None
    agent_url = effective_agent_url(db, settings)
    new_key = request.session.pop("new_key", None)
    return _render(
        request,
        3,
        agent_url=agent_url,
        console_url=effective_console_url(db, settings),
        agent_pin=pin,
        package=latest_package(settings.data_dir / "downloads"),
        orgs=db.scalars(select(Organization).order_by(Organization.name)).all(),
        enrollment_code=make_code(agent_url, new_key, pin) if new_key else None,
    )


@router.post("/setup/agent/key")
def setup_agent_key(
    request: Request,
    customer: str = Form(""),
    organization_id: str = Form(""),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    org = db.get(Organization, int(organization_id)) if organization_id.isdigit() else None
    name = customer.strip()[:128]
    if org is None and name:
        org = db.scalar(select(Organization).where(Organization.name == name))
        if org is None:
            org = Organization(name=name)
            db.add(org)
            db.flush()
            audit(db, user.username, "customer.created", target=org.name, ip=_ip(request))
    value = create_enrollment_key(
        db,
        user,
        f"First firewall{' - ' + org.name if org else ''}",
        organization_id=org.id if org else None,
        expires_days=7,
        max_uses=1,
        ip=_ip(request),
    )
    db.commit()
    request.session["new_key"] = value
    return redirect("/setup/agent")


@router.post("/setup/finish")
def setup_finish(
    request: Request,
    skipped: bool = Form(False),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    site = get_site_settings(db)
    if not site.setup_completed_at:
        site.setup_completed_at = utcnow().isoformat()
        site.setup_completed_by = user.username
        save_site_settings(db, site, user.username)
    audit(db, user.username, "setup.skipped" if skipped else "setup.finished", ip=_ip(request))
    db.commit()
    flash(
        request,
        "Setup skipped. You can run it again from Settings." if skipped
        else "Setup finished. Firewalls appear here as they enroll.",
        "info" if skipped else "success",
    )
    return redirect("/")
