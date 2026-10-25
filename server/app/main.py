from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from .api import agent as agent_api
from .api.rest import create_rest_app
from .config import Settings, get_settings
from .db import init_engine, session_factory, upgrade_schema
from .models import Role, User
from .proxyproto import ClientAddressMiddleware
from .scheduler import scheduler_loop
from .security import generate_temporary_password, hash_password
from .services.agentpkg import ensure_package
from .web import (
    account_routes,
    apikey_routes,
    config_routes,
    customer_routes,
    schedule_routes,
    mfa_routes,
    setup_routes,
    sso_routes,
    terminal_routes,
)
from .web import routes as web_routes
from .web.auth import LoginRequired, MfaSetupRequired, PasswordChangeRequired

log = logging.getLogger("comsense")


def bootstrap_admin(settings: Settings) -> str | None:
    """Create the first admin with a random one-time password and log it.

    Every install gets its own password, written once to the log (docker logs /
    journalctl). It must be changed at first sign-in. Returns the password if
    an admin was created.
    """
    with session_factory()() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return None
        password = generate_temporary_password()
        db.add(
            User(
                username=settings.initial_admin_user,
                password_hash=hash_password(password),
                role=Role.admin,
                must_change_password=True,
            )
        )
        db.commit()
    banner = "=" * 64
    log.warning(
        "\n%s\n  ComSense first start: initial administrator created\n"
        "    username: %s\n    password: %s\n"
        "  This one-time password must be changed at first sign-in.\n%s",
        banner, settings.initial_admin_user, password, banner,
    )
    return password


def init_backend(settings: Settings) -> None:
    """Validate settings, prepare storage and the database. Call once per process."""
    settings.validate()
    settings.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (settings.data_dir / "downloads").mkdir(parents=True, exist_ok=True)
    ensure_package(settings.data_dir / "downloads")
    engine = init_engine(settings.database_url)
    upgrade_schema(engine)
    bootstrap_admin(settings)


def _mount_downloads(app: FastAPI, settings: Settings) -> None:
    # Built agent packages placed here are offered to firewalls for installation.
    app.mount("/downloads", StaticFiles(directory=settings.data_dir / "downloads"), name="downloads")


def create_web_app(settings: Settings) -> FastAPI:
    """The admin console. Plain HTTP; publish it only through an HTTPS reverse proxy."""

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(scheduler_loop(settings)) if settings.run_scheduler else None
        yield
        if task:
            task.cancel()

    app = FastAPI(
        title="ComSense Firewall Manager",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.state.settings = settings
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="csfm_session",
        max_age=settings.session_max_age,
        same_site="strict",
        https_only=settings.secure_cookies,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'",
        )
        if settings.secure_cookies:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if not request.url.path.startswith(("/static/", "/brand/")):
            # Pages show recovery codes, setup keys and configurations: keep them out of browser caches.
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(PasswordChangeRequired)
    async def password_change_required(request: Request, exc: PasswordChangeRequired):
        return RedirectResponse("/account", status_code=303)

    @app.exception_handler(MfaSetupRequired)
    async def mfa_setup_required(request: Request, exc: MfaSetupRequired):
        web_routes.flash(request, "Two-factor sign-in is required for your account. Set it up to continue.", "warn")
        return RedirectResponse("/account#mfa", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return web_routes.render(
            request, "error.html", status_code=exc.status_code, code=exc.status_code, message=exc.detail
        )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    _mount_downloads(app, settings)
    # REST API for scripts and integrations (API keys; no cookies, so no CSRF).
    app.mount("/api/v1", create_rest_app(settings))
    app.include_router(account_routes.router)
    app.include_router(apikey_routes.router)
    app.include_router(config_routes.router)
    app.include_router(customer_routes.router)
    app.include_router(mfa_routes.router)
    app.include_router(schedule_routes.router)
    app.include_router(setup_routes.router)
    app.include_router(sso_routes.router)
    app.include_router(sso_routes.public)
    app.include_router(terminal_routes.router)
    app.include_router(terminal_routes.ws_router)
    app.include_router(web_routes.router)
    return app


def create_agent_app(settings: Settings) -> FastAPI:
    """The agent API, served on its own TLS port. Nothing else is reachable through it."""
    app = FastAPI(
        title="ComSense agent API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.dependency_overrides[get_settings] = lambda: settings

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    _mount_downloads(app, settings)
    app.include_router(agent_api.router)
    # Real client addresses for connections relayed by the PROXY protocol front listener.
    app.add_middleware(ClientAddressMiddleware)
    return app


def create_app(settings: Settings | None = None) -> FastAPI:
    """Initialise the backend and return the web console app (used by tests and tools)."""
    settings = settings or get_settings()
    init_backend(settings)
    return create_web_app(settings)
