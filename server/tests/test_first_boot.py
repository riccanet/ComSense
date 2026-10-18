from __future__ import annotations

import logging
import re

from conftest import ADMIN_PASSWORD, csrf_from, login
from fastapi.testclient import TestClient
from sqlalchemy import Boolean, Column, Integer, MetaData, String, Table, create_engine, inspect, select

from app.db import session_factory, upgrade_schema
from app.main import create_app
from app.models import User


def _first_boot(settings, caplog):
    with caplog.at_level(logging.WARNING, logger="comsense"):
        app = create_app(settings)
    m = re.search(r"username: (\S+)\s+password: (\S+)", caplog.text)
    assert m, "the one-time password must be written to the log"
    return app, m.group(1), m.group(2)


def _sign_in(c, username, password):
    token = csrf_from(c.get("/login").text)
    return c.post("/login", data={"username": username, "password": password, "csrf_token": token}, follow_redirects=False)


def test_first_boot_password_is_random_logged_and_must_be_changed(settings, tmp_path, caplog):
    app, username, password = _first_boot(settings, caplog)
    assert username == "admin" and len(password) == 20
    with session_factory()() as db:
        admin = db.scalar(select(User))
        assert admin.must_change_password

    with TestClient(app, base_url="https://testserver") as c:
        resp = _sign_in(c, username, password)
        assert resp.status_code == 303 and resp.headers["location"] == "/account"
        # Every other page sends the user back until the password is changed.
        for path in ("/", "/devices", "/keys", "/users"):
            r = c.get(path, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"] == "/account", path
        page = c.get("/account").text
        assert "temporary password" in page
        csrf = csrf_from(page)
        same = c.post("/account/password", data={"current": password, "new": password, "confirm": password, "csrf_token": csrf})
        assert "different" in same.text
        done = c.post(
            "/account/password",
            data={"current": password, "new": ADMIN_PASSWORD, "confirm": ADMIN_PASSWORD, "csrf_token": csrf},
            follow_redirects=False,
        )
        assert done.status_code == 303 and done.headers["location"] == "/setup"
        assert c.get("/devices").status_code == 200

    # A second install gets a different password; a restart does not create another.
    caplog.clear()
    other = settings.__class__(**{**settings.__dict__, "database_url": f"sqlite:///{tmp_path / 'other.db'}"})
    _, _, other_password = _first_boot(other, caplog)
    assert other_password != password
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="comsense"):
        create_app(other)
    assert "password:" not in caplog.text


def test_admin_assigned_passwords_are_temporary(client, db):
    csrf = login(client)
    client.post("/users", data={"username": "alice", "password": "temporary-pass-1", "role": "operator", "csrf_token": csrf})
    alice = db.scalar(select(User).where(User.username == "alice"))
    assert alice.must_change_password
    client.post("/logout", data={"csrf_token": csrf})
    resp = _sign_in(client, "alice", "temporary-pass-1")
    assert resp.headers["location"] == "/account"


def test_upgrade_adds_new_columns_to_an_existing_database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    # A users table as created by an earlier version, with a row in it.
    old = MetaData()
    Table(
        "users", old,
        Column("id", Integer, primary_key=True), Column("username", String(64)),
        Column("password_hash", String(255)), Column("role", String(8)), Column("active", Boolean),
    )
    old.create_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("INSERT INTO users (username, password_hash, role, active) VALUES ('a', 'x', 'admin', 1)")

    added = upgrade_schema(engine)
    assert "users.must_change_password" in added
    assert "must_change_password" in {c["name"] for c in inspect(engine).get_columns("users")}
    with engine.begin() as conn:
        assert conn.exec_driver_sql("SELECT must_change_password FROM users").scalar() in (0, False)
    assert upgrade_schema(engine) == []
