"""Run the web console and the agent listener in one process.

    python -m app.serve

The web console listens on CSFM_WEB_HOST:CSFM_WEB_PORT (plain HTTP, for an HTTPS
reverse proxy), the MCP server on CSFM_MCP_HOST:CSFM_MCP_PORT (the same; 0 turns it off). The agent API listens on CSFM_AGENT_HOST:CSFM_AGENT_PORT and
terminates TLS itself. Both share the database and one housekeeping scheduler,
so run a single process.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import socket

import uvicorn

from .config import get_settings
from .db import session_factory
from .main import create_agent_app, create_web_app, init_backend
from .proxyproto import TrustedNetworks, make_front_handler
from .services.appsettings import agent_tls_names, effective_agent_url, get_agent_network_settings
from .tls import ensure_agent_tls

log = logging.getLogger("comsense")


class _Server(uvicorn.Server):
    # Signals are handled once below for both servers.
    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def serve() -> None:
    settings = get_settings()
    init_backend(settings)
    with session_factory()() as db:
        tls_names = agent_tls_names(db)
        agent_url = effective_agent_url(db, settings)
    tls = ensure_agent_tls(settings, extra_names=tls_names)
    log.info(
        "Agent listener on port %d (%s certificate, pin sha256//%s); firewalls use %s",
        settings.agent_port,
        "self-issued" if tls.self_signed else "provided",
        tls.pin,
        agent_url,
    )

    web = _Server(
        uvicorn.Config(
            create_web_app(settings),
            host=settings.web_host,
            port=settings.web_port,
            proxy_headers=True,
            forwarded_allow_ips=settings.forwarded_allow_ips,
            server_header=False,
        )
    )
    # The agent port is served by a small front listener that understands PROXY
    # protocol headers from trusted proxies and relays the TLS stream unchanged to
    # the agent app on a loopback socket.
    inner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    inner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    inner.bind(("127.0.0.1", 0))
    inner_port = inner.getsockname()[1]

    def trusted_loader() -> list[str]:
        with session_factory()() as db:
            return get_agent_network_settings(db).trusted_proxies

    front = await asyncio.start_server(
        make_front_handler("127.0.0.1", inner_port, TrustedNetworks(trusted_loader)),
        host=settings.agent_host,
        port=settings.agent_port,
        reuse_address=True,
    )
    agent = _Server(
        uvicorn.Config(
            create_agent_app(settings),
            ssl_certfile=str(tls.cert_file),
            ssl_keyfile=str(tls.key_file),
            # Client addresses come from the front listener (ClientAddressMiddleware).
            proxy_headers=False,
            server_header=False,
            timeout_keep_alive=15,
        )
    )

    servers = [web, agent]
    mcp = None
    if settings.mcp_port:
        from .mcp_server import create_mcp_app  # noqa: PLC0415 - only when the MCP port is on

        mcp = _Server(
            uvicorn.Config(
                create_mcp_app(settings),
                host=settings.mcp_host,
                port=settings.mcp_port,
                proxy_headers=True,
                forwarded_allow_ips=settings.forwarded_allow_ips,
                server_header=False,
            )
        )
        servers.append(mcp)
        log.info("MCP server on %s:%d (/mcp, API keys from Settings > API keys)", settings.mcp_host, settings.mcp_port)

    loop = asyncio.get_running_loop()

    def stop() -> None:
        for server in servers:
            server.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    try:
        await asyncio.gather(web.serve(), agent.serve(sockets=[inner]), *([mcp.serve()] if mcp else []))
    finally:
        front.close()
        await front.wait_closed()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(serve())


if __name__ == "__main__":
    main()
