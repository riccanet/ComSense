"""Run the web console and the agent listener in one process.

    python -m app.serve

The web console listens on CSFM_WEB_HOST:CSFM_WEB_PORT (plain HTTP, for an HTTPS
reverse proxy). The agent API listens on CSFM_AGENT_HOST:CSFM_AGENT_PORT and
terminates TLS itself. Both share the database and one housekeeping scheduler,
so run a single process.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal

import uvicorn

from .config import get_settings
from .main import create_agent_app, create_web_app, init_backend
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
    tls = ensure_agent_tls(settings)
    log.info(
        "Agent listener on port %d (%s certificate, pin sha256//%s); firewalls use %s",
        settings.agent_port,
        "self-issued" if tls.self_signed else "provided",
        tls.pin,
        settings.agent_url,
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
    agent = _Server(
        uvicorn.Config(
            create_agent_app(settings),
            host=settings.agent_host,
            port=settings.agent_port,
            ssl_certfile=str(tls.cert_file),
            ssl_keyfile=str(tls.key_file),
            # Agents connect directly, so the socket address is the real client.
            proxy_headers=False,
            server_header=False,
            timeout_keep_alive=15,
        )
    )

    loop = asyncio.get_running_loop()

    def stop() -> None:
        web.should_exit = True
        agent.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    await asyncio.gather(web.serve(), agent.serve())


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(serve())


if __name__ == "__main__":
    main()
