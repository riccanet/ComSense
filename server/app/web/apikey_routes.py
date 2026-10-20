"""Settings > API keys: keys for the REST API (/api/v1) and the MCP server."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db
from ..models import ApiKey, Role, User, utcnow
from ..services import apiops
from ..services.appsettings import effective_console_url
from .auth import flash, require, verify_csrf
from .routes import _ip, redirect, render

router = APIRouter(dependencies=[Depends(verify_csrf)])
admin = require(Role.admin)


@router.get("/settings/api-keys", response_class=HTMLResponse)
def api_keys_page(request: Request, settings: Settings = Depends(get_settings), user: User = Depends(admin),
                  db: Session = Depends(get_db)):
    keys = db.scalars(select(ApiKey).order_by(ApiKey.revoked, ApiKey.created_at.desc())).all()
    return render(request, "settings_api_keys.html", section="/settings/api-keys", keys=keys,
                  new_key=request.session.pop("new_api_key", None), now=utcnow(),
                  roles=[Role.viewer, Role.operator, Role.admin],
                  api_url=effective_console_url(db, settings).rstrip("/") + "/api/v1", mcp_port=settings.mcp_port)


@router.post("/settings/api-keys")
def api_keys_create(request: Request, name: str = Form(...), role: str = Form("viewer"),
                    expires_days: int = Form(0), user: User = Depends(admin), db: Session = Depends(get_db)):
    if role not in Role.__members__:
        raise HTTPException(400, "Unknown role")
    key, value = apiops.create_key(db, name, Role(role), user.username, expires_days if expires_days > 0 else None)
    db.flush()
    audit(db, user.username, "api_key.created", target=key.prefix, detail=f"{key.name} ({key.role.value})",
          ip=_ip(request))
    db.commit()
    request.session["new_api_key"] = value  # shown once, on the next page load only
    return redirect("/settings/api-keys")


@router.post("/settings/api-keys/{key_id:int}/revoke")
def api_keys_revoke(key_id: int, request: Request, user: User = Depends(admin), db: Session = Depends(get_db)):
    key = db.get(ApiKey, key_id)
    if key is None:
        raise HTTPException(404, "API key not found")
    key.revoked = True
    audit(db, user.username, "api_key.revoked", target=key.prefix, detail=key.name, ip=_ip(request))
    db.commit()
    flash(request, f"Revoked {key.name}. Anything using it is refused from now on.", "success")
    return redirect("/settings/api-keys")
