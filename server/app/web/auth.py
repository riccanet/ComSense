"""Session authentication, roles and CSRF protection for the web UI."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Role, User
from ..security import csrf_matches, new_csrf_token

ROLE_RANK = {Role.viewer: 0, Role.operator: 1, Role.admin: 2}


class LoginRequired(Exception):
    pass


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = new_csrf_token()
        request.session["csrf"] = token
    return token


async def verify_csrf(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    form = await request.form()
    supplied = form.get("csrf_token") or request.headers.get("x-csrf-token")
    if not csrf_matches(request.session.get("csrf"), str(supplied) if supplied else None):
        raise HTTPException(403, "Invalid or missing CSRF token; reload the page and try again")


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("uid")
    user = db.get(User, user_id) if user_id else None
    if user is None or not user.active or request.session.get("pwv") != user.password_hash[-16:]:
        request.session.clear()
        raise LoginRequired()
    request.state.user = user
    return user


def require(role: Role):
    def checker(request: Request, user: User = Depends(current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[role]:
            raise HTTPException(403, f"This action requires the {role.value} role")
        return user

    return checker


def flash(request: Request, message: str, category: str = "info") -> None:
    request.session.setdefault("flash", []).append([category, message])


def pop_flashes(request: Request) -> list[list[str]]:
    return request.session.pop("flash", [])
