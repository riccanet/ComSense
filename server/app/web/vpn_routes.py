"""VPN pages: every tunnel of one firewall with connect / disconnect / reconnect, and the fleet's tunnels."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import Device, DeviceStatus, Role, TaskType, User
from ..services import vpn as vpn_svc
from ..services.tasks import TaskError, queue_task
from .auth import flash, require, verify_csrf
from .routes import _device_page_token, _get_device, _ip, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
viewer = require(Role.viewer)
operator = require(Role.operator)


@router.get("/devices/{device_id}/vpn", response_class=HTMLResponse)
def device_vpn(device_id: str, request: Request, user: User = Depends(viewer), db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    return render(request, "device_vpn.html", device=device, page_token=_device_page_token(db, device),
                  vpn=vpn_svc.report(device), tunnels=vpn_svc.tunnels(device), reported=vpn_svc.reported(device),
                  kind_names=vpn_svc.KIND_NAMES, human_bytes=vpn_svc.human_bytes, human_seconds=vpn_svc.human_seconds)


@router.post("/devices/{device_id}/vpn")
def device_vpn_control(
    device_id: str,
    request: Request,
    kind: str = Form(...),
    tunnel: str = Form(...),
    action: str = Form(...),
    peer: str = Form(""),
    client: str = Form(""),
    settings: Settings = Depends(get_settings),
    user: User = Depends(operator),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    back = f"/devices/{device_id}/vpn"
    try:
        payload = vpn_svc.control_payload(device, kind, tunnel, action, peer=peer, client=client)
        task = queue_task(db, device, TaskType.vpn_control, payload, actor=user.username,
                          changes_enabled=settings.enable_firewall_changes)
    except (vpn_svc.VpnError, TaskError) as exc:
        db.rollback()
        flash(request, str(exc), "error")
        return redirect(back)
    db.flush()
    audit(db, user.username, "task.vpn_control", target=device.id, detail=json.dumps(payload), ip=_ip(request))
    db.commit()
    what = vpn_svc.ACTION_NAMES[action].lower()
    flash(request, f"Queued: {what} {payload.get('user') or payload['name']} (task #{task.id}). The firewall runs it "
                   "within seconds; this page updates when it reports back.", "success")
    return redirect(back)


@router.get("/vpn", response_class=HTMLResponse)
def fleet_vpn(request: Request, show: str = "all", user: User = Depends(viewer), db: Session = Depends(get_db)):
    """Every firewall's tunnels, problems first."""
    devices = db.scalars(select(Device).options(selectinload(Device.organization))
                         .where(Device.status != DeviceStatus.pending)).all()
    rows = []
    for d in devices:
        for t in vpn_svc.tunnels(d):
            if show == "problems" and not t.problem:
                continue
            rows.append((d, t))
    rows.sort(key=lambda r: (not r[1].problem, r[1].status == "up", (r[0].organization.name if r[0].organization
                                                                     else "~").lower(), r[0].name.lower(),
                             r[1].kind, r[1].name.lower()))
    reporting = sum(1 for d in devices if vpn_svc.reported(d))
    problems = sum(1 for d in devices for t in vpn_svc.tunnels(d) if t.problem)
    return render(request, "vpn.html", rows=rows, show=show, reporting=reporting, total=len(devices),
                  problems=problems)
