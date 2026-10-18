from __future__ import annotations

import logging
from collections.abc import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def init_engine(url: str) -> Engine:
    global _engine, _SessionLocal
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    assert _engine is not None, "init_engine() has not been called"
    return _engine


def session_factory() -> sessionmaker[Session]:
    assert _SessionLocal is not None, "init_engine() has not been called"
    return _SessionLocal


def get_db() -> Iterator[Session]:
    db = session_factory()()
    try:
        yield db
    finally:
        db.close()


log = logging.getLogger("comsense.db")


def upgrade_schema(engine: Engine) -> list[str]:
    """Create missing tables and add columns that newer versions introduced.

    Only additive changes are handled (new tables, new columns). A new NOT NULL
    column must declare a server_default so existing rows can be filled.
    Returns the columns that were added.
    """
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    added: list[str] = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                ddl_type = column.type.compile(dialect=engine.dialect)
                ddl = f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {ddl_type}'
                if column.server_default is not None:
                    default = column.server_default.arg
                    default_sql = default.compile(dialect=engine.dialect) if hasattr(default, "compile") else f"'{default}'"
                    ddl += f" DEFAULT {default_sql}"
                    if not column.nullable:
                        ddl += " NOT NULL"
                conn.execute(text(ddl))
                added.append(f"{table.name}.{column.name}")
                log.warning("Database upgraded: added column %s.%s", table.name, column.name)
    return added
