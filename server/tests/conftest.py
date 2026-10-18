from __future__ import annotations

import os

import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.api import agent as agent_api  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_factory  # noqa: E402
from app.main import create_agent_app, create_app  # noqa: E402
from app.models import EnrollmentKey, User  # noqa: E402
from app.security import (  # noqa: E402
    hash_password,
    generate_enrollment_key,
    generate_fernet_key,
    hash_secret,
    key_display_prefix,
)
from app.web import routes as web_routes  # noqa: E402

ADMIN_PASSWORD = "correct horse battery staple"


def pytest_configure(config):
    config.addinivalue_line("markers", "changes: run with CSFM_ENABLE_FIREWALL_CHANGES on")


# Run the suite against PostgreSQL (as in production) with e.g.
#   CSFM_TEST_DATABASE_URL=postgresql+psycopg://postgres@/csfm_test?host=/tmp&port=55432
# Every test starts from empty tables.
TEST_DATABASE_URL = os.environ.get("CSFM_TEST_DATABASE_URL", "")


def _fresh_database(url: str) -> str:
    from sqlalchemy import create_engine

    from app.models import Base

    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    engine.dispose()
    return url


@pytest.fixture
def settings(tmp_path: Path, request) -> Settings:
    return Settings(
        enable_firewall_changes=request.node.get_closest_marker("changes") is not None,
        database_url=_fresh_database(TEST_DATABASE_URL) if TEST_DATABASE_URL else f"sqlite:///{tmp_path / 'test.db'}",
        secret_key="x" * 48,
        backup_encryption_key=generate_fernet_key(),
        data_dir=tmp_path / "data",
        public_url="https://comsense.test",
        secure_cookies=False,
        run_scheduler=False,
        initial_admin_user="admin",
    )


@pytest.fixture
def client(settings: Settings):
    agent_api.enroll_limiter.reset()
    web_routes.login_limiter.reset()
    agent_api.auth_failure_limiter.reset()
    app = create_app(settings)
    # First start created "admin" with a random one-time password; give it a known
    # permanent one so tests can sign in. test_first_boot.py covers the real flow.
    with session_factory()() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        admin.password_hash = hash_password(ADMIN_PASSWORD)
        admin.must_change_password = False
        db.commit()
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture
def agent(client, settings):
    """Client for the agent listener (a separate app on its own TLS port)."""
    with TestClient(create_agent_app(settings), base_url="https://testserver:10443") as c:
        yield c


@pytest.fixture
def db(client):
    with session_factory()() as session:
        yield session


def make_key(db, **kwargs) -> str:
    value = generate_enrollment_key()
    db.add(
        EnrollmentKey(
            name=kwargs.pop("name", "test"),
            prefix=key_display_prefix(value),
            key_hash=hash_secret(value),
            **kwargs,
        )
    )
    db.commit()
    return value


SYSTEM = {
    "hostname": "fw1.example.com",
    "edition": "ce",
    "version": "2.7.2-RELEASE",
    "platform": "pfSense",
    "unique_id": "abc123",
}
ALL_CAPS = ["backup", "policy", "upgrade", "packages", "services", "restore", "reboot"]


def enroll(client, key: str, system=None, capabilities=None) -> dict:
    resp = client.post(
        "/api/agent/v1/enroll",
        json={
            "enrollment_key": key,
            "agent_version": "0.1.0",
            "system": system or SYSTEM,
            "capabilities": ALL_CAPS if capabilities is None else capabilities,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def csrf_from(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "no csrf token on page"
    return m.group(1)


def login(client, username="admin", password=ADMIN_PASSWORD) -> str:
    token = csrf_from(client.get("/login").text)
    resp = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    assert resp.status_code == 303, resp.text
    return csrf_from(client.get("/").text)
