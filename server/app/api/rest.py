"""The REST API for scripts and integrations: /api/v1 on the web console's address.

Authenticated with an API key (Settings > API keys) in "Authorization: Bearer csfm_api_...". No
cookies, so no CSRF. The OpenAPI description is at /api/v1/openapi.json. The work itself is in
services/apiops.py, shared with the MCP server.
"""
from __future__ import annotations

from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import __version__
from ..config import Settings, get_settings
from ..db import get_db
from ..security import RateLimiter
from ..services import apiops
from ..services.apiops import ApiError, Principal

# Failed keys per client address.
auth_failures = RateLimiter(limit=20, window_seconds=300)


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    ip = _ip(request)
    if auth_failures.blocked(ip):
        raise HTTPException(429, "Too many failed API keys; wait a few minutes")
    who = apiops.authenticate(db, request.headers.get("authorization", ""), ip)
    if who is None:
        auth_failures.allow(ip)
        raise HTTPException(401, "Send a valid API key: Authorization: Bearer csfm_api_...",
                            headers={"WWW-Authenticate": "Bearer"})
    return who


class RunTask(BaseModel):
    task: str = Field(description="One of: " + ", ".join(sorted(apiops.RUNNABLE)))
    package: str = Field("", description="For install_package / remove_package: pfSense-pkg-...")
    service: str = Field("", description="For restart_service: the service name")
    boot_environment: str = Field("", description="For remove_boot_environment: its name, from the firewall's "
                                                  "boot_environments")


class SetCustomer(BaseModel):
    customer_id: int | None = Field(description="The customer's id, or null to leave the firewall unassigned")


def create_rest_app(settings: Settings) -> FastAPI:
    app = FastAPI(
        title="ComSense Firewall Manager API",
        version=__version__,
        description="Firewalls, customers, alerts and tasks. Authenticate with an API key from Settings > API "
                    "keys: `Authorization: Bearer csfm_api_...`. Viewer keys read; operator and admin keys "
                    "can also queue tasks, acknowledge alerts and assign customers.",
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json",
    )
    app.dependency_overrides[get_settings] = lambda: settings

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    read = [Depends(principal)]

    @app.get("/firewalls", dependencies=read, summary="List firewalls (by customer, then name)")
    def firewalls(customer_id: int | None = None, status: str | None = Query(None, description="online, offline, pending, disabled"),
                  search: str | None = None, agent_outdated: bool = False,
                  db: Session = Depends(get_db)) -> list[dict[str, Any]]:
        return apiops.list_firewalls(db, settings, customer_id, status, search, agent_outdated)

    @app.get("/firewalls/{firewall_id}", dependencies=read, summary="One firewall with its inventory")
    def firewall(firewall_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
        return apiops.get_firewall(db, settings, firewall_id)

    @app.get("/firewalls/{firewall_id}/tasks", dependencies=read, summary="A firewall's recent tasks")
    def firewall_tasks(firewall_id: str, limit: int = 50, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
        return apiops.list_tasks(db, firewall_id, limit)

    @app.post("/firewalls/{firewall_id}/tasks", status_code=201, summary="Queue a task (operator)")
    def firewall_run_task(firewall_id: str, request: Request, body: RunTask, who: Principal = Depends(principal),
                          db: Session = Depends(get_db)) -> dict[str, Any]:
        return apiops.run_task(db, settings, who, firewall_id, body.task, body.package, body.service, _ip(request),
                               body.boot_environment)

    @app.put("/firewalls/{firewall_id}/customer", summary="Assign a firewall to a customer (operator)")
    def firewall_customer(firewall_id: str, request: Request, body: SetCustomer = Body(...),
                          who: Principal = Depends(principal), db: Session = Depends(get_db)) -> dict[str, Any]:
        return apiops.set_customer(db, who, firewall_id, body.customer_id, _ip(request))

    @app.get("/firewalls/{firewall_id}/backups", dependencies=read, summary="A firewall's configuration backups")
    def firewall_backups(firewall_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
        return apiops.list_backups(db, firewall_id)

    @app.get("/tasks/{task_id}", dependencies=read, summary="One task, with its output")
    def task(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
        return apiops.get_task(db, task_id)

    @app.get("/customers", dependencies=read, summary="List customers")
    def customers(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
        return apiops.list_customers(db)

    @app.get("/customers/{customer_id}", dependencies=read, summary="One customer with its firewalls")
    def customer(customer_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
        return apiops.get_customer(db, settings, customer_id)

    @app.get("/alerts", dependencies=read, summary="Alerts, newest first (open ones by default)")
    def alerts(open_only: bool = True, firewall_id: str | None = None, limit: int = 200,
               db: Session = Depends(get_db)) -> list[dict[str, Any]]:
        return apiops.list_alerts(db, open_only, firewall_id, limit)

    @app.post("/alerts/{alert_id}/acknowledge", summary="Acknowledge an alert (operator)")
    def alert_ack(alert_id: int, request: Request, who: Principal = Depends(principal),
                  db: Session = Depends(get_db)) -> dict[str, Any]:
        return apiops.acknowledge_alert(db, who, alert_id, _ip(request))

    @app.get("/configurations", dependencies=read, summary="Configurations (policies)")
    def configurations(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
        return apiops.list_configurations(db)

    @app.get("/tasks-available", dependencies=read, summary="The task names POST /firewalls/{id}/tasks accepts")
    def runnable() -> dict[str, str]:
        return {name: label for name, (_, label) in apiops.RUNNABLE.items()}

    return app
