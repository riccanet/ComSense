"""The MCP server: ComSense for AI assistants, on its own port (CSFM_MCP_PORT, default 8090).

Streamable HTTP at /mcp, stateless, authenticated with the same API keys as the REST API
("Authorization: Bearer csfm_api_..."); the key's role decides what the tools may do. The tools call
services/apiops.py, so they behave exactly like the REST API.
"""
from __future__ import annotations

import contextvars
import json
import logging
from typing import Any

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from . import __version__
from .config import Settings
from .db import session_factory
from .security import RateLimiter
from .services import apiops
from .services.apiops import ApiError, Principal

log = logging.getLogger("comsense.mcp")

_principal: contextvars.ContextVar[Principal | None] = contextvars.ContextVar("csfm_mcp_principal", default=None)
_client_ip: contextvars.ContextVar[str] = contextvars.ContextVar("csfm_mcp_ip", default="")
auth_failures = RateLimiter(limit=20, window_seconds=300)

INSTRUCTIONS = (
    "ComSense Firewall Manager: monitoring and management of pfSense firewalls for many customers. "
    "Start with list_firewalls or list_customers; firewall ids are UUIDs. Tasks (run_task) are queued and "
    "run on the firewall within seconds to minutes: follow them with get_task. Reboots and upgrades "
    "interrupt the customer's network, so confirm them with the user first."
)
READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
RISKY = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)


def _run(fn, *args, **kwargs) -> Any:
    """Run one operation with its own database session; ApiError becomes the tool's error message."""
    with session_factory()() as db:
        try:
            return fn(db, *args, **kwargs)
        except ApiError as exc:
            raise ToolError(exc.message) from exc


async def _call(fn, *args, **kwargs) -> Any:
    # In a worker thread (the database is synchronous); the context, and with it the caller, goes along.
    return await anyio.to_thread.run_sync(lambda: _run(fn, *args, **kwargs))


def _who() -> Principal:
    who = _principal.get()
    if who is None:  # the HTTP layer refuses unauthenticated requests before any tool runs
        raise ToolError("Not authenticated")
    return who


def build_server(settings: Settings) -> MCPServer:
    server = MCPServer("ComSense Firewall Manager", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(annotations=READ)
    async def list_firewalls(customer_id: int | None = None, status: str | None = None, search: str | None = None,
                             agent_outdated_only: bool = False) -> list[dict[str, Any]]:
        """List firewalls, by customer then name, with status, versions, WAN addresses and open alerts.
        status: online, offline, pending or disabled. search matches name, hostname or WAN IP."""
        _who()
        return await _call(apiops.list_firewalls, settings, customer_id, status, search, agent_outdated_only)

    @server.tool(annotations=READ)
    async def get_firewall(firewall_id: str) -> dict[str, Any]:
        """One firewall in detail: interfaces, gateways, services, packages, metrics and pfSense updates."""
        _who()
        return await _call(apiops.get_firewall, settings, firewall_id)

    @server.tool(annotations=READ)
    async def list_customers() -> list[dict[str, Any]]:
        """List customers with their contact details and number of firewalls."""
        _who()
        return await _call(apiops.list_customers)

    @server.tool(annotations=READ)
    async def get_customer(customer_id: int) -> dict[str, Any]:
        """One customer with its firewalls."""
        _who()
        return await _call(apiops.get_customer, settings, customer_id)

    @server.tool(annotations=READ)
    async def list_alerts(open_only: bool = True, firewall_id: str | None = None,
                          limit: int = 100) -> list[dict[str, Any]]:
        """Alerts (gateway down, firewall offline, ...), newest first; open ones unless open_only is false."""
        _who()
        return await _call(apiops.list_alerts, open_only, firewall_id, limit)

    @server.tool(annotations=WRITE)
    async def acknowledge_alert(alert_id: int) -> dict[str, Any]:
        """Mark an alert as acknowledged (needs an operator or admin key)."""
        who = _who()
        return await _call(apiops.acknowledge_alert, who, alert_id, _client_ip.get())

    @server.tool(annotations=READ)
    async def list_tasks(firewall_id: str, limit: int = 20) -> list[dict[str, Any]]:
        """A firewall's recent tasks with their status and output."""
        _who()
        return await _call(apiops.list_tasks, firewall_id, limit)

    @server.tool(annotations=READ)
    async def get_task(task_id: int) -> dict[str, Any]:
        """One task: pending, sent, running, success or failed, with the firewall's output."""
        _who()
        return await _call(apiops.get_task, task_id)

    @server.tool(annotations=RISKY)
    async def run_task(firewall_id: str, task: str, package: str = "", service: str = "",
                       boot_environment: str = "") -> dict[str, Any]:
        """Queue a task on a firewall (needs an operator or admin key). task is one of: check_now, backup,
        check_updates, update_agent, upgrade_packages, upgrade_system (reboots), reboot, restart_service
        (with service), install_package / remove_package (with package, pfSense-pkg-...), free_disk_space
        (package cache and old logs), remove_boot_environment (with boot_environment, a name from
        get_firewall's boot_environments; admin key; never the active or next-boot one). Reboots and
        upgrades interrupt the customer's network: confirm with the user first. Follow up with get_task."""
        who = _who()
        return await _call(apiops.run_task, settings, who, firewall_id, task, package, service, _client_ip.get(),
                           boot_environment)

    @server.tool(annotations=READ)
    async def list_backups(firewall_id: str) -> list[dict[str, Any]]:
        """A firewall's stored configuration backups (metadata only)."""
        _who()
        return await _call(apiops.list_backups, firewall_id)

    @server.tool(annotations=WRITE)
    async def assign_customer(firewall_id: str, customer_id: int | None) -> dict[str, Any]:
        """Put a firewall under a customer, or none with customer_id null (needs an operator or admin key)."""
        who = _who()
        return await _call(apiops.set_customer, who, firewall_id, customer_id, _client_ip.get())

    @server.tool(annotations=READ)
    async def list_configurations() -> list[dict[str, Any]]:
        """Configurations (policies such as aliases, firewall rules and port forwards) defined in ComSense."""
        _who()
        return await _call(apiops.list_configurations)

    return server


def create_mcp_app(settings: Settings):
    """The ASGI app for the MCP port: refuses requests without a valid API key, then serves /mcp."""
    server = build_server(settings)
    inner = server.streamable_http_app(
        stateless_http=True,
        json_response=True,
        # Requests are authenticated with a bearer key and served through the admin's own proxy name,
        # so the Host header is not restricted (DNS rebinding cannot carry the key).
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        ip = (scope.get("client") or ("", 0))[0]
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
        if auth_failures.blocked(ip):
            return await _deny(send, 429, "Too many failed API keys; wait a few minutes")

        def check() -> Principal | None:
            with session_factory()() as db:
                return apiops.authenticate(db, headers.get("authorization", ""), ip)

        who = await anyio.to_thread.run_sync(check)
        if who is None:
            auth_failures.allow(ip)
            return await _deny(send, 401, "Send a ComSense API key: Authorization: Bearer csfm_api_...")
        tokens = (_principal.set(who), _client_ip.set(ip))
        try:
            await inner(scope, receive, send)
        finally:
            _client_ip.reset(tokens[1])
            _principal.reset(tokens[0])

    return app


async def _deny(send, status: int, message: str) -> None:
    body = json.dumps({"error": message}).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"), (b"www-authenticate", b"Bearer"),
        (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
