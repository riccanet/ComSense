"""Customers: each customer groups the firewalls it owns (stored as Organization)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..audit import audit
from ..db import get_db
from ..models import Alert, Backup, Device, DeviceStatus, EnrollmentKey, Organization, Role, User, utcnow
from .auth import flash, require, verify_csrf
from .routes import _ip, redirect, render, valid_email

router = APIRouter(dependencies=[Depends(verify_csrf)])
viewer = require(Role.viewer)
operator = require(Role.operator)
admin = require(Role.admin)


def _get(db: Session, customer_id: int) -> Organization:
    org = db.get(Organization, customer_id)
    if org is None:
        raise HTTPException(404, "Customer not found")
    return org


def _clean_contact(request: Request, contact_email: str) -> str | None:
    contact_email = contact_email.strip()
    if contact_email and not valid_email(contact_email):
        flash(request, "The contact email is not a valid address.", "error")
        return None
    return contact_email


@router.get("/organizations", include_in_schema=False)
def old_customers_url():
    return RedirectResponse("/customers", status_code=301)


@router.get("/customers", response_class=HTMLResponse)
def customers_page(request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    status_counts: dict[int | None, dict[str, int]] = {}
    for org_id, status, n in db.execute(
        select(Device.organization_id, Device.status, func.count()).group_by(Device.organization_id, Device.status)
    ):
        status_counts.setdefault(org_id, {})[status.value] = n
    alert_counts = dict(
        db.execute(
            select(Device.organization_id, func.count())
            .select_from(Alert)
            .join(Device)
            .where(Alert.resolved_at.is_(None))
            .group_by(Device.organization_id)
        ).all()
    )
    return render(
        request,
        "customers.html",
        customers=db.scalars(select(Organization).order_by(Organization.name)).all(),
        status_counts=status_counts,
        alert_counts=alert_counts,
        unassigned=sum(status_counts.get(None, {}).values()),
    )


@router.post("/customers")
def customers_create(
    request: Request,
    name: str = Form(...),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    contact_phone: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    email = _clean_contact(request, contact_email)
    if email is None or not name.strip():
        if email is not None:
            flash(request, "Enter a customer name.", "error")
        return redirect("/customers")
    org = Organization(
        name=name.strip()[:128],
        contact_name=contact_name.strip()[:128],
        contact_email=email,
        contact_phone=contact_phone.strip()[:64],
        notes=notes,
    )
    db.add(org)
    try:
        db.flush()
        audit(db, user.username, "customer.created", target=org.name, ip=_ip(request))
        db.commit()
    except IntegrityError:
        db.rollback()
        flash(request, "A customer with that name already exists.", "error")
        return redirect("/customers")
    flash(request, f"Customer {org.name} added. Create an enrollment key for it to connect its firewalls.", "success")
    return redirect(f"/customers/{org.id}")


@router.get("/customers/{customer_id}", response_class=HTMLResponse)
def customer_detail(customer_id: int, request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    org = _get(db, customer_id)
    devices = db.scalars(select(Device).where(Device.organization_id == org.id).order_by(Device.name)).all()
    ids = [d.id for d in devices]
    alerts = (
        db.scalars(
            select(Alert)
            .where(Alert.device_id.in_(ids), Alert.resolved_at.is_(None))
            .order_by(Alert.severity.asc(), Alert.opened_at.desc())
        ).all()
        if ids
        else []
    )
    last_backup = (
        dict(
            db.execute(
                select(Backup.device_id, func.max(Backup.created_at)).where(Backup.device_id.in_(ids)).group_by(Backup.device_id)
            ).all()
        )
        if ids
        else {}
    )
    keys = db.scalars(
        select(EnrollmentKey).where(EnrollmentKey.organization_id == org.id).order_by(EnrollmentKey.id.desc())
    ).all()
    return render(
        request,
        "customer.html",
        customer=org,
        devices=devices,
        alerts=alerts,
        last_backup=last_backup,
        keys=keys,
        online=sum(1 for d in devices if d.status == DeviceStatus.online),
        updates=sum(1 for d in devices if (d.updates or {}).get("update_available")),
        now=utcnow(),
    )


@router.post("/customers/{customer_id}")
def customer_update(
    customer_id: int,
    request: Request,
    name: str = Form(...),
    contact_name: str = Form(""),
    contact_email: str = Form(""),
    contact_phone: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    org = _get(db, customer_id)
    email = _clean_contact(request, contact_email)
    if email is None:
        return redirect(f"/customers/{org.id}")
    org.name = name.strip()[:128] or org.name
    org.contact_name = contact_name.strip()[:128]
    org.contact_email = email
    org.contact_phone = contact_phone.strip()[:64]
    org.notes = notes
    try:
        audit(db, user.username, "customer.updated", target=org.name, ip=_ip(request))
        db.commit()
        flash(request, "Customer saved.", "success")
    except IntegrityError:
        db.rollback()
        flash(request, "Another customer already has that name.", "error")
    return redirect(f"/customers/{org.id}")


@router.post("/customers/{customer_id}/delete")
def customer_delete(customer_id: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    org = _get(db, customer_id)
    if org.devices:
        flash(request, "Move its firewalls to another customer, or delete them, first.", "error")
        return redirect(f"/customers/{org.id}")
    for key in db.scalars(select(EnrollmentKey).where(EnrollmentKey.organization_id == org.id)):
        key.revoked = True
        key.organization_id = None
    db.delete(org)
    audit(db, user.username, "customer.deleted", target=org.name, ip=_ip(request))
    db.commit()
    flash(request, "Customer deleted; its enrollment keys were revoked.", "success")
    return redirect("/customers")
