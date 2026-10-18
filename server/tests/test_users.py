from __future__ import annotations

import re

from conftest import login

from app.models import Role, User
from app.security import hash_password, verify_password


def _add(db, name="op", **kw):
    u = User(username=name, password_hash=hash_password("operator-password-1"), role=Role.operator, **kw)
    db.add(u)
    db.commit()
    return u


def test_user_list_links_to_a_page_per_user(client, db):
    csrf = login(client)
    op = _add(db, email="op@example.com")
    page = client.get("/users").text
    assert f'href="/users/{op.id}"' in page and 'action="/users"' in page  # the add-user form stays
    assert 'name="role"' not in page.split("Add user")[0]  # role and password live on the user's page
    row = re.search(rf'id="flags-{op.id}".*?</tr>', page, re.S).group(0)
    assert 'name="active"' in row and 'name="email_alerts"' in row

    # The list's checkboxes save straight away.
    client.post(f"/users/{op.id}/flags", data={"email_alerts": "true", "csrf_token": csrf})
    db.expire_all()
    op = db.get(User, op.id)
    assert not op.active and op.email_alerts

    page = client.get(f"/users/{op.id}").text
    for text in (f'action="/users/{op.id}"', f'action="/users/{op.id}/password"', "Two-factor"):
        assert text in page
    r = client.post(f"/users/{op.id}", data={"role": "admin", "active": "true", "email": "op@example.com",
                                             "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == f"/users/{op.id}"
    r = client.post(f"/users/{op.id}/password", data={"password": "short", "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == f"/users/{op.id}"
    client.post(f"/users/{op.id}/password", data={"password": "a-new-temporary-pass", "csrf_token": csrf})
    db.expire_all()
    op = db.get(User, op.id)
    assert op.role == Role.admin and op.active and not op.email_alerts
    assert verify_password("a-new-temporary-pass", op.password_hash) and op.must_change_password


def test_alerts_need_an_email_and_admins_cannot_lock_themselves_out(client, db):
    csrf = login(client)
    op = _add(db)
    page = client.get("/users").text
    row = re.search(rf'id="flags-{op.id}".*?</tr>', page, re.S).group(0)
    assert re.search(r'name="email_alerts"[^>]*disabled', row)
    client.post(f"/users/{op.id}/flags", data={"active": "true", "email_alerts": "true", "csrf_token": csrf})
    db.expire_all()
    assert not db.get(User, op.id).email_alerts

    me = db.query(User).filter_by(username="admin").one()
    client.post(f"/users/{me.id}/flags", data={"csrf_token": csrf})
    db.expire_all()
    assert db.get(User, me.id).active
    assert client.get("/users/99999").status_code == 404
