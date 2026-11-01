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
    async def get_nat_rules(firewall_id: str) -> dict[str, Any]:
        """A firewall's NAT: port forwards (id for update_port_forward/remove_port_forward, interface, protocol, source, destination and port, internal target and
        port, description, disabled, associated filter rule), outbound NAT (mode: automatic, hybrid, advanced or
        disabled, and its rules) and 1:1 mappings. Read from the firewall's newest configuration backup, which
        the firewall uploads whenever its configuration changes."""
        _who()
        return await _call(apiops.get_nat_rules, settings, firewall_id)

    @server.tool(annotations=RISKY)
    async def add_port_forward(firewall_id: str, port: str, target: str, interface: str = "wan", protocol: str = "tcp",
                               local_port: str = "", source: str = "any", source_port: str = "",
                               destination: str = "wan address", description: str = "",
                               disabled: bool = False) -> dict[str, Any]:
        """Add a port forward (needs an operator or admin key): external port (a number, range 8000-8100 or port
        alias) on interface (name like WAN/VERIZON or id like wan/opt1) to target (internal IP or alias) and
        local_port (default: the external port). Source restricts who may connect (address, network or alias).
        The firewall applies it within seconds under probation (undone if it then loses contact with ComSense),
        with a linked pass rule. Confirm with the user first; follow up with get_task, then get_nat_rules."""
        who = _who()
        fields = {"port": port, "target": target, "interface": interface, "protocol": protocol,
                  "local_port": local_port, "source": source, "source_port": source_port,
                  "destination": destination, "description": description, "disabled": disabled}
        return await _call(apiops.add_port_forward, settings, who, firewall_id, fields, _client_ip.get())

    @server.tool(annotations=RISKY)
    async def update_port_forward(firewall_id: str, forward_id: str, port: str | None = None, target: str | None = None,
                                  interface: str | None = None, protocol: str | None = None,
                                  local_port: str | None = None, source: str | None = None,
                                  source_port: str | None = None, destination: str | None = None,
                                  description: str | None = None, disabled: bool | None = None) -> dict[str, Any]:
        """Change a port forward (needs an operator or admin key); forward_id is its id from get_nat_rules. Only
        the fields given change (disabled=true turns it off without removing it). Port forwards from ComSense
        Configurations are changed there instead. Confirm with the user first; follow up with get_task."""
        who = _who()
        fields = {"port": port, "target": target, "interface": interface, "protocol": protocol,
                  "local_port": local_port, "source": source, "source_port": source_port,
                  "destination": destination, "description": description, "disabled": disabled}
        return await _call(apiops.edit_port_forward, settings, who, firewall_id, forward_id, fields, _client_ip.get())

    @server.tool(annotations=RISKY)
    async def remove_port_forward(firewall_id: str, forward_id: str) -> dict[str, Any]:
        """Remove a port forward and its linked filter rule (needs an operator or admin key); forward_id is its id
        from get_nat_rules. Confirm with the user first; follow up with get_task."""
        who = _who()
        return await _call(apiops.remove_port_forward, settings, who, firewall_id, forward_id, _client_ip.get())

    @server.tool(annotations=READ)
    async def get_config(firewall_id: str, path: str = "", depth: int = 3) -> dict[str, Any]:
        """Read any part of a pfSense firewall's configuration (config.xml) as structured data, from its current
        backup; passwords and keys show as "[hidden]". Without a path: the top-level sections (system,
        interfaces, filter, nat, aliases, dhcpd, unbound, openvpn, ipsec, gateways, staticroutes, vlans,
        virtualip, syslog, snmpd, ntpd, captiveportal, ...). Paths are slash-separated, with list items by
        index: "system", "interfaces/opt1", "filter/rule/3", "dhcpd/lan/staticmap", "unbound/hosts/0".
        Subtrees deeper than `depth` are outlined; read a deeper path to see them. Read before edit_config, and
        use the same paths and indexes there. "editable" says whether edit_config may change the path."""
        _who()
        return await _call(apiops.get_config, settings, firewall_id, path, depth)

    @server.tool(annotations=RISKY)
    async def edit_config(firewall_id: str, operations: list[dict[str, Any]], summary: str = "") -> dict[str, Any]:
        """Edit any setting pfSense's own pages edit (needs an admin key), as operations on the same paths
        get_config shows, applied together:
          {"op": "set", "path": "system/timezone", "value": "America/New_York"}  replace a value or subtree
          {"op": "set", "path": "interfaces/opt2/enable", "value": false}       false removes a flag (true sets it)
          {"op": "delete", "path": "filter/rule/7"}                             remove (later items move up)
          {"op": "append", "path": "dhcpd/lan/staticmap", "value": {"mac": "...", "ipaddr": "...", "descr": "..."}}
          {"op": "insert", "path": "filter/rule/0", "value": {...}}           add before an item (0: first)
        Operations apply in order, each seeing the ones before it (an insert moves later list items down); if
        any fails, none is applied. Add "expect": {"descr": "..."} to an operation on a list item so it is refused if that index now holds
        something else. Values use pfSense's own field names (read a similar existing item first). Never edited:
        package settings (installedpackages), user accounts, groups, authentication servers, certificates, cron
        and shell commands. Secrets read as "[hidden]" must not be sent back. The firewall applies the edit
        within seconds, reloads what it affects (rules, interfaces, DHCP, DNS, VPNs...), and undoes it
        automatically if it then loses contact with ComSense (probation). Changes the customer's live network:
        confirm the exact operations with the user first; follow up with get_task, then get_config."""
        who = _who()
        return await _call(apiops.edit_config, settings, who, firewall_id, operations, summary, _client_ip.get())

    @server.tool(annotations=READ)
    async def get_firewall_rules(firewall_id: str, interface: str = "") -> dict[str, Any]:
        """A firewall's rules (Firewall > Rules) in its order, optionally for one interface by name (WAN, LAN,
        GUEST, Floating, OpenVPN...), with the aliases they can use and their entries. From the newest
        configuration backup."""
        _who()
        return await _call(apiops.get_firewall_rules, settings, firewall_id, interface)

    @server.tool(annotations=READ)
    async def find_device(query: str) -> list[dict[str, Any]]:
        """Find a device on every firewall's network by MAC address (any notation, or part of one), IP address
        or hostname: ARP entries, DHCP leases and DHCP static mappings, with the firewall and interface. Firewalls
        report these every few minutes (run_task check_now for fresh ones)."""
        _who()
        return await _call(apiops.find_device, query)

    @server.tool(annotations=READ)
    async def get_network(firewall_id: str, query: str = "") -> dict[str, Any]:
        """One firewall's ARP entries, DHCP leases and static mappings, optionally filtered by MAC, IP or name."""
        _who()
        return await _call(apiops.get_network, firewall_id, query)

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
