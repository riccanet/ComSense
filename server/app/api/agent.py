"""HTTPS API used by the pfSense agent.

All calls except /enroll authenticate with the per-device bearer token issued at
enrollment. The token is stored hashed; possession of an enrollment key is the
only way to obtain one.
"""
from __future__ import annotations

import asyncio
import gzip
import json
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, WebSocket
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import __version__
from ..audit import audit
from ..config import Settings, get_settings
from ..db import get_db, session_factory
from ..models import (
    Backup,
    Device,
    DeviceStatus,
    EnrollmentKey,
    Metric,
    Task,
    TaskStatus,
    TaskType,
    aware,
    utcnow,
)
from ..security import RateLimiter, generate_device_token, hash_secret
from ..services import agentpkg
from ..services import terminal as terminal_svc
from ..services import alerts as alert_svc
from ..services.backups import BackupError, load_backup, prune_backups, store_backup
from ..services.policies import reconcile_device_policies
from ..services.tasks import take_pending_tasks, task_to_wire

router = APIRouter(prefix="/api/agent/v1", tags=["agent"])

MAX_JSON_BODY = 2 * 1024 * 1024
TOKEN_MAX_AGE = timedelta(days=30)
KNOWN_CAPABILITIES = {"backup", "policy", "upgrade", "packages", "services", "restore", "reboot", "shell"}

enroll_limiter = RateLimiter(limit=10, window_seconds=600)
# Addresses that keep presenting bad device tokens are refused for a while.
auth_failure_limiter = RateLimiter(limit=20, window_seconds=600)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def wan_addresses(interfaces: list[Any]) -> list[str]:
    """The firewall's WAN addresses, main one first: the interface named wan, then every other interface
    with a gateway (a second WAN, such as a backup line). With dual WAN the "wan" interface may be the one
    that is down, and the working line another (opt1, ...)."""
    found = []
    candidates = [i for i in interfaces if isinstance(i, dict)]
    candidates.sort(key=lambda i: i.get("name") != "wan")
    for i in candidates:
        ip = str(i.get("ipaddr") or "").strip()
        if ip and (i.get("name") == "wan" or str(i.get("gateway") or "").strip()) and ip not in found:
            found.append(ip)
    return found


async def read_body(request: Request, limit: int, message: str = "Request body too large") -> bytes:
    """The request body, refused as soon as it passes `limit` (also when it is sent without a length)."""
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isdigit():
            raise HTTPException(400, "Invalid Content-Length")
        if int(length) > limit:
            raise HTTPException(413, message)
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, message)
        chunks.append(chunk)
    return b"".join(chunks)


async def read_json(request: Request) -> dict[str, Any]:
    body = await read_body(request, MAX_JSON_BODY)
    try:
        data = json.loads(body or b"{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Body must be JSON") from exc
    if not isinstance(data, dict):
        raise HTTPException(400, "Body must be a JSON object")
    return data


def current_device(
    request: Request,
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Device:
    ip = client_ip(request)
    if auth_failure_limiter.blocked(ip):
        raise HTTPException(429, "Too many failed authentication attempts; try again later")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        auth_failure_limiter.allow(ip)
        raise HTTPException(401, "Missing device token", headers={"WWW-Authenticate": "Bearer"})
    device = db.scalar(select(Device).where(Device.token_hash == hash_secret(token.strip())))
    if device is None:
        auth_failure_limiter.allow(ip)
        raise HTTPException(401, "Unknown device token", headers={"WWW-Authenticate": "Bearer"})
    if device.status == DeviceStatus.disabled:
        raise HTTPException(403, "Device has been disabled on the management server")
    device.last_seen_at = utcnow()
    device.last_seen_ip = ip
    return device


def require_approved(device: Device) -> None:
    if device.status == DeviceStatus.pending:
        raise HTTPException(403, "Device is waiting for approval")


def _str(value: Any, limit: int = 255) -> str:
    return str(value)[:limit] if value is not None else ""


def _apply_system_info(device: Device, data: dict[str, Any]) -> None:
    system = data.get("system") or {}
    device.hostname = _str(system.get("hostname")) or device.hostname
    device.edition = _str(system.get("edition"), 32) or device.edition
    device.product_version = _str(system.get("version"), 64) or device.product_version
    device.platform = _str(system.get("platform"), 128) or device.platform
    device.arch = _str(system.get("arch"), 32) or device.arch
    device.serial = _str(system.get("serial"), 128) or device.serial
    device.agent_version = _str(data.get("agent_version"), 32) or device.agent_version
    if "capabilities" in data and isinstance(data["capabilities"], list):
        device.capabilities = sorted(KNOWN_CAPABILITIES & {str(c) for c in data["capabilities"]})


@router.post("/enroll")
async def enroll(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    ip = client_ip(request)
    if not enroll_limiter.allow(ip):
        raise HTTPException(429, "Too many enrollment attempts; try again later")
    data = await read_json(request)
    key_value = str(data.get("enrollment_key", "")).strip()
    key = (
        db.scalar(select(EnrollmentKey).where(EnrollmentKey.key_hash == hash_secret(key_value)))
        if key_value
        else None
    )
    if key is None or not key.usable():
        audit(db, "anonymous", "enroll.rejected", detail="invalid or expired enrollment key", ip=ip)
        db.commit()
        raise HTTPException(403, "Enrollment key is invalid, expired or revoked")

    system = data.get("system") or {}
    unique_id = _str(system.get("unique_id"), 128)
    token = generate_device_token()
    device = None
    if unique_id:
        # A reinstalled firewall keeps its hardware id; reattach it to its history.
        device = db.scalar(
            select(Device).where(
                Device.unique_id == unique_id,
                Device.organization_id == key.organization_id,
                Device.status != DeviceStatus.disabled,
            )
        )
    reenrolled = device is not None
    if device is None:
        device = Device(
            name=_str(system.get("hostname"), 128) or "pfSense",
            unique_id=unique_id,
            organization_id=key.organization_id,
            token_hash=hash_secret(token),
        )
        db.add(device)
    device.token_hash = hash_secret(token)
    device.token_rotated_at = utcnow()
    device.enrollment_key_id = key.id
    # Taking over an existing firewall's record (and its queued tasks) always needs an admin's approval:
    # its unique id is not a secret, so anyone with an enrollment key could claim it otherwise.
    device.status = DeviceStatus.pending if key.require_approval or reenrolled else DeviceStatus.online
    device.last_seen_at = utcnow()
    device.last_seen_ip = ip
    device.applied_policies = {} if not reenrolled else device.applied_policies
    _apply_system_info(device, data)

    key.use_count += 1
    key.last_used_at = utcnow()
    db.flush()
    audit(
        db,
        "system",
        "device.reenrolled" if reenrolled else "device.enrolled",
        target=device.id,
        detail=f"hostname={device.hostname} key={key.prefix} approval={key.require_approval}",
        ip=ip,
    )
    db.commit()
    return {
        "device_id": device.id,
        "token": token,
        "status": device.status.value,
        "checkin_interval": settings.checkin_interval,
        "server_version": __version__,
    }


@router.post("/checkin")
async def checkin(
    request: Request,
    device: Device = Depends(current_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    data = await read_json(request)
    _apply_system_info(device, data)
    response: dict[str, Any] = {
        "status": device.status.value,
        "checkin_interval": settings.checkin_interval,
        "server_time": utcnow().isoformat(),
        "tasks": [],
    }
    if device.status == DeviceStatus.pending:
        db.commit()
        return response
    device.status = DeviceStatus.online

    inventory = {
        k: data[k]
        for k in ("system", "interfaces", "gateways", "services", "carp", "metrics", "packages", "change_guard", "processes",
                  "update_branch", "ddns")
        if k in data
    }
    if inventory:
        device.inventory = inventory
        if isinstance(data.get("interfaces"), list):
            addresses = wan_addresses(data["interfaces"])
            device.wan_ip = _str(addresses[0] if addresses else "", 64)
    if isinstance(data.get("updates"), dict):
        device.updates = data["updates"]
    if isinstance(data.get("applied_policies"), dict):
        device.applied_policies = {str(k): str(v) for k, v in data["applied_policies"].items()}

    metrics = data.get("metrics") or {}
    if metrics:
        load = metrics.get("load") or [None]
        db.add(
            Metric(
                device_id=device.id,
                cpu_pct=_num(metrics.get("cpu_pct")),
                mem_pct=_num(metrics.get("mem_pct")),
                disk_pct=_num(metrics.get("disk_pct")),
                load1=_num(load[0] if isinstance(load, list) and load else None),
                states=_int(metrics.get("states")),
                states_max=_int(metrics.get("states_max")),
                uptime=_int(metrics.get("uptime")),
            )
        )
    alert_svc.evaluate_report(db, device, data)
    alert_svc.record_rollbacks(db, device, data.get("rollbacks"))

    config = data.get("config") or {}
    if config.get("sha256") and config["sha256"] != device.config_sha256:
        response["upload_backup"] = True  # config changed since our last stored copy

    reconcile_device_policies(db, device, changes_enabled=settings.enable_firewall_changes)
    db.flush()
    response["tasks"] = [task_to_wire(t) for t in take_pending_tasks(db, device)]
    if utcnow() - aware(device.token_rotated_at) > TOKEN_MAX_AGE:
        response["rotate_token"] = True
    db.commit()
    return response


@router.get("/ping")
def ping(device: Device = Depends(current_device), db: Session = Depends(get_db)) -> dict[str, bool]:
    """Cheap authenticated call the agent uses to confirm it can still reach us after a change."""
    db.commit()
    return {"ok": True}


WAIT_MAX = 55  # seconds; below common proxy and NAT idle timeouts
WAIT_POLL = 2.0


def _has_pending_task(device_id: str) -> bool:
    with session_factory()() as db:
        return db.scalar(
            select(Task.id).where(Task.device_id == device_id, Task.status == TaskStatus.pending).limit(1)
        ) is not None


def _authenticate(request: Request, authorization: str) -> str:
    with session_factory()() as db:
        device = current_device(request, authorization, db)
        db.commit()
        return device.id


@router.get("/wait")
async def wait_for_work(request: Request, timeout: int = 50, authorization: str = Header(default="")) -> dict[str, bool]:
    """Long poll between check-ins: answers as soon as a task is queued for this device (e.g. the
    console's "Check now"), or after `timeout` seconds. The firewall still only connects out.
    Holds no database connection while waiting, so many waiting firewalls cost little."""
    device_id = await asyncio.to_thread(_authenticate, request, authorization)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(1, min(timeout, WAIT_MAX))
    while True:
        if await asyncio.to_thread(_has_pending_task, device_id):
            return {"wake": True}
        if loop.time() >= deadline:
            return {"wake": False}
        await asyncio.sleep(min(WAIT_POLL, max(0.0, deadline - loop.time())))


@router.get("/agent-package/{name}")
def agent_package(
    name: str,
    device: Device = Depends(current_device),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
):
    """The agent package for self-updates (update_agent tasks), over the authenticated API."""
    db.commit()
    if not agentpkg.PACKAGE_RE.fullmatch(name):
        raise HTTPException(404, "No such package")
    downloads = settings.data_dir / "downloads"
    path = downloads / name
    if not path.is_file():
        raise HTTPException(404, "No such package")
    if agentpkg.needs_bootstrap(device.agent_version):
        # The same file name, as the old agent insists on it; the content installs the real package.
        m = agentpkg.PACKAGE_RE.fullmatch(name)
        path = agentpkg.bootstrap_package(downloads, {"name": name, "version": m.group(1)})
    return FileResponse(path, media_type="application/octet-stream")


@router.websocket("/terminal/{sid}")
async def terminal_socket(websocket: WebSocket, sid: str, settings: Settings = Depends(get_settings)) -> None:
    """The firewall end of a remote terminal session (services/terminal.py), opened by the agent's
    terminal helper after an open_terminal task. Authenticated with the device token."""
    ip = websocket.client.host if websocket.client else ""
    if auth_failure_limiter.blocked(ip):
        await websocket.close(code=1008)
        return
    device_id = await asyncio.to_thread(
        terminal_svc.check_agent, sid, websocket.headers.get("authorization", "")
    )
    if device_id is None:
        auth_failure_limiter.allow(ip)
        await websocket.close(code=1008)
        return
    await websocket.accept()
    await terminal_svc.serve_agent(sid, websocket, settings.data_dir)


@router.post("/token/rotate")
def rotate_token(
    request: Request, device: Device = Depends(current_device), db: Session = Depends(get_db)
) -> dict[str, str]:
    token = generate_device_token()
    device.token_hash = hash_secret(token)
    device.token_rotated_at = utcnow()
    audit(db, "system", "device.token_rotated", target=device.id, ip=client_ip(request))
    db.commit()
    return {"token": token}


@router.post("/tasks/{task_id}/result")
async def task_result(
    task_id: int,
    request: Request,
    device: Device = Depends(current_device),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    require_approved(device)
    data = await read_json(request)
    task = db.get(Task, task_id)
    if task is None or task.device_id != device.id:
        raise HTTPException(404, "Unknown task")
    if task.status not in (TaskStatus.sent, TaskStatus.running):
        return {"status": task.status.value}
    try:
        status = TaskStatus(data.get("status", ""))
    except ValueError as exc:
        raise HTTPException(400, "status must be running, success or failed") from exc
    if status not in (TaskStatus.running, TaskStatus.success, TaskStatus.failed):
        raise HTTPException(400, "status must be running, success or failed")
    task.status = status
    task.output = _str(data.get("output"), 64_000)
    if (task.type == TaskType.update_agent and status == TaskStatus.failed
            and "is already installed" in (task.output or "")):
        # Agents up to 0.2.9 ran a plain `pkg add`, which pkg refuses over an installed package.
        task.output += ("\n\nThis agent version cannot update itself in place. Install the new package once "
                        "by hand (Settings > Enrollment keys shows the command; it uses pkg-static add -f); "
                        "later versions update themselves.")
    result = data.get("result")
    if isinstance(result, dict):
        if status == TaskStatus.running and isinstance(result.get("progress"), dict):
            # When the upgrade last moved on: alerts.check_stalled_upgrades raises an alert when it stops.
            result["progress_at"] = utcnow().isoformat()
        task.result = result
    if status != TaskStatus.running:
        task.finished_at = utcnow()
    if task.type == TaskType.check_updates and status == TaskStatus.success and isinstance(result, dict):
        device.updates = result
    if task.type in (TaskType.apply_policy, TaskType.remove_policy) and status == TaskStatus.success:
        applied = dict(device.applied_policies or {})
        if task.type == TaskType.apply_policy:
            policy = task.payload.get("policy", {})
            applied[str(policy.get("id"))] = policy.get("hash", "")
        else:
            applied.pop(str(task.payload.get("policy_id")), None)
        device.applied_policies = applied
    db.commit()
    return {"status": task.status.value}


@router.post("/backups")
async def upload_backup(
    request: Request,
    device: Device = Depends(current_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    x_csfm_sha256: str = Header(default=""),
    x_csfm_reason: str = Header(default="manual"),
    x_csfm_task_id: str = Header(default=""),
) -> dict[str, Any]:
    require_approved(device)
    body = await read_body(request, settings.max_backup_bytes, "Backup too large")
    task_id = int(x_csfm_task_id) if x_csfm_task_id.isdigit() else None
    if task_id is not None:
        task = db.get(Task, task_id)
        if task is None or task.device_id != device.id:
            task_id = None
    try:
        backup, created = store_backup(db, settings, device, body, x_csfm_sha256, x_csfm_reason, task_id)
    except BackupError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.flush()
    if created:
        prune_backups(db, settings, device)
        audit(db, "system", "backup.stored", target=device.id, detail=f"backup={backup.id}")
    db.commit()
    return {"backup_id": backup.id, "sha256": backup.sha256, "created": created}


@router.get("/backups/{backup_id}")
def download_backup_for_restore(
    backup_id: int,
    device: Device = Depends(current_device),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Only served while a restore task for this exact backup is in flight."""
    require_approved(device)
    backup = db.get(Backup, backup_id)
    if backup is None or backup.device_id != device.id:
        raise HTTPException(404, "Unknown backup")
    open_restore = db.scalar(
        select(Task.id).where(
            Task.device_id == device.id,
            Task.type == TaskType.restore_backup,
            Task.status.in_((TaskStatus.sent, TaskStatus.running)),
        )
    )
    restore_task = db.get(Task, open_restore) if open_restore else None
    if restore_task is None or restore_task.payload.get("backup_id") != backup.id:
        raise HTTPException(403, "No restore of this backup has been requested")
    data = gzip.compress(load_backup(settings, backup))
    return Response(
        content=data,
        media_type="application/gzip",
        headers={"X-CSFM-SHA256": backup.sha256},
    )


def _num(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
