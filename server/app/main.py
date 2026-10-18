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
from .config import Settings, get_settings
from .db import Base, init_engine, session_factory
from .models import Role, User
from .scheduler import scheduler_loop
from .security import hash_password
from .web import routes as web_routes
from .web.auth import LoginRequired

log = logging.getLogger("pfmanager")


def bootstrap_admin(settings: Settings) -> None:
    with session_factory()() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return
        if not settings.initial_admin_password:
            log.warning("No users exist. Set PFM_INITIAL_ADMIN_PASSWORD to create the first admin.")
            return
        db.add(
            User(
                username=settings.initial_admin_user,
                password_hash=hash_password(settings.initial_admin_password),
                role=Role.admin,
            )
        )
        db.commit()
        log.warning("Created initial admin user '%s'. Change its password.", settings.initial_admin_user)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.validate()
    settings.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    engine = init_engine(settings.database_url)
    Base.metadata.create_all(engine)
    bootstrap_admin(settings)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(scheduler_loop(settings)) if settings.run_scheduler else None
        yield
        if task:
            task.cancel()

    app = FastAPI(
        title="PfManager",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.dependency_overrides[get_settings] = lambda: settings
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="pfm_session",
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
        return response

    @app.exception_handler(LoginRequired)
    async def login_required(request: Request, exc: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
        return web_routes.render(
            request, "error.html", status_code=exc.status_code, code=exc.status_code, message=exc.detail
        )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    # Built agent packages placed here can be installed with `pkg-static add <url>`.
    downloads = settings.data_dir / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    app.mount("/downloads", StaticFiles(directory=downloads), name="downloads")
    app.include_router(agent_api.router)
    app.include_router(web_routes.router)
    return app


def app_factory() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
