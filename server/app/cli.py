"""Administrative commands: `python -m app.cli <command>`."""
from __future__ import annotations

import argparse
import getpass
import secrets
import sys

from sqlalchemy import select

from .config import get_settings
from .db import Base, init_engine, session_factory
from .models import Role, User
from .security import generate_fernet_key, hash_password


def cmd_keygen(_: argparse.Namespace) -> int:
    print(f"PFM_SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"PFM_BACKUP_ENCRYPTION_KEY={generate_fernet_key()}")
    return 0


def cmd_create_user(args: argparse.Namespace) -> int:
    settings = get_settings()
    engine = init_engine(settings.database_url)
    Base.metadata.create_all(engine)
    password = args.password or getpass.getpass("Password: ")
    if len(password) < 12:
        print("Password must be at least 12 characters", file=sys.stderr)
        return 1
    with session_factory()() as db:
        user = db.scalar(select(User).where(User.username == args.username))
        if user is None:
            user = User(username=args.username)
            db.add(user)
        user.password_hash = hash_password(password)
        user.role = Role(args.role)
        user.active = True
        db.commit()
    print(f"User '{args.username}' saved with role {args.role}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pfmanager")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("keygen", help="print fresh PFM_SECRET_KEY and PFM_BACKUP_ENCRYPTION_KEY values")
    cu = sub.add_parser("create-user", help="create a user or reset an existing user's password")
    cu.add_argument("username")
    cu.add_argument("--role", choices=[r.value for r in Role], default="admin")
    cu.add_argument("--password", help="omit to be prompted")
    args = parser.parse_args(argv)
    return {"keygen": cmd_keygen, "create-user": cmd_create_user}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
