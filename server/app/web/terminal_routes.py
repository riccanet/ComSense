"""Remote terminal pages: approve a session with an authenticator code, the live terminal, and the
replay of recorded sessions. The relay itself lives in services/terminal.py."""
from __future__ import annotations

import asyncio
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import Device, DeviceStatus, Role, TaskType, TerminalSession, TerminalStatus, User
from ..security import RateLimiter
from ..services import mfa
from ..services import terminal as terminal_svc
from ..services.tasks import TaskError, queue_task
from .auth import flash, require, verify_csrf
from .routes import _get_device, _ip, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
ws_router = APIRouter()
admin = require(Role.admin)
approve_limiter = RateLimiter(limit=5, window_seconds=900)  # wrong codes per admin

# xterm.js adds <style> elements for its layout and colours; scripts stay 'self' only.
TERMINAL_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'"
)
SESSION_KEY = "terminals"  # session ids this browser approved


def terminal_blocker(device: Device, user: User) -> str:
    """Why this admin cannot open a terminal on this firewall right now ("" if they can)."""
    if not user.totp_enabled:
        return "totp"
    if "shell" not in (device.capabilities or []):
        return "permission"
    if device.status != DeviceStatus.online:
        return "offline"
    return ""


def recent_sessions(db: Session, device_id: str, limit: int = 10) -> list[TerminalSession]:
    return list(db.scalars(
        select(TerminalSession).where(TerminalSession.device_id == device_id)
        .order_by(TerminalSession.created_at.desc()).limit(limit)
    ))


@router.get("/devices/{device_id}/terminal", response_class=HTMLResponse)
def terminal_approve_page(device_id: str, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    device = _get_device(db, device_id)
    return render(request, "terminal_approve.html", device=device, blocker=terminal_blocker(device, user))


@router.post("/devices/{device_id}/terminal")
def terminal_approve(
    device_id: str,
    request: Request,
    code: str = Form(""),
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    device = _get_device(db, device_id)
    back = f"/devices/{device_id}/terminal"
    if terminal_blocker(device, user):
        return redirect(back)
    key = f"terminal:{user.id}"
    if approve_limiter.blocked(key):
        flash(request, "Too many wrong codes. Try again in 15 minutes.", "error")
        return redirect(back)
    if not mfa.verify_user_totp(user, code, settings.secret_key):
        approve_limiter.allow(key)
        audit(db, user.username, "terminal.denied", target=device.id, detail="wrong authenticator code", ip=_ip(request))
        db.commit()
        flash(request, "That code is not valid. Enter the current code from your authenticator app.", "error")
        return redirect(back)
    sid = secrets.token_urlsafe(24)
    try:
        queue_task(db, device, TaskType.open_terminal, {"session": sid}, actor=user.username,
                   pickup_window=timedelta(seconds=terminal_svc.START_WINDOW))
    except TaskError as exc:
        db.rollback()
        flash(request, str(exc), "error")
        return redirect(back)
    db.add(TerminalSession(id=sid, device_id=device.id, user_id=user.id, username=user.username,
                           browser_ip=_ip(request), recording=f"{sid}.cast"))
    audit(db, user.username, "terminal.approve", target=device.id,
          detail=f"session {sid[:8]} approved with authenticator code", ip=_ip(request))
    db.commit()
    request.session[SESSION_KEY] = [*request.session.get(SESSION_KEY, [])[-4:], sid]
    return redirect(f"/terminal/{sid}")


def _session(db: Session, sid: str) -> TerminalSession:
    ts = db.get(TerminalSession, sid)
    if ts is None:
        raise HTTPException(404, "Terminal session not found")
    return ts


@router.get("/terminal/{sid}", response_class=HTMLResponse)
def terminal_page(sid: str, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    ts = _session(db, sid)
    live = (
        ts.status == TerminalStatus.approved
        and ts.user_id == user.id
        and sid in request.session.get(SESSION_KEY, [])
        and terminal_svc._fresh(ts)
    )
    response = render(request, "terminal.html", ts=ts, device=ts.device, live=live)
    response.headers["Content-Security-Policy"] = TERMINAL_CSP
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/terminal/{sid}/recording")
def terminal_recording(
    sid: str,
    download: int = 0,
    settings: Settings = Depends(get_settings),
    user: User = Depends(admin),
    db: Session = Depends(get_db),
):
    ts = _session(db, sid)
    path = terminal_svc.recording_dir(settings.data_dir) / ts.recording if ts.recording else None
    if path is None or not path.is_file():
        raise HTTPException(404, "No recording for this session")
    name = f"terminal-{ts.device.name}-{ts.created_at:%Y%m%d-%H%M}.cast" if download else None
    return FileResponse(path, media_type="application/x-asciicast", filename=name,
                        headers={"Cache-Control": "no-store"})


@ws_router.websocket("/terminal/{sid}/ws")
async def terminal_socket(websocket: WebSocket, sid: str, settings: Settings = Depends(get_settings)) -> None:
    # Browsers send cookies with cross-site WebSocket requests; only our own pages may connect.
    origin = urlsplit(websocket.headers.get("origin", ""))
    if not origin.netloc or origin.netloc != websocket.headers.get("host", ""):
        await websocket.close(code=1008)
        return
    session = websocket.session
    allowed = await asyncio.to_thread(
        terminal_svc.check_browser, sid, session.get("uid"), session.get("pwv"), sid in session.get(SESSION_KEY, [])
    )
    if not allowed:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    await terminal_svc.serve_browser(sid, websocket, settings.data_dir)
