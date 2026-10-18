"""Runtime configuration, read from environment variables.

Every setting has a CSFM_ prefix. See deploy/.env.example for a documented list.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "CSFM_DATABASE_URL", "postgresql+psycopg://comsense:comsense@localhost:5432/comsense"
        )
    )
    # Signs web session cookies. Must be long and random in production.
    secret_key: str = field(default_factory=lambda: os.environ.get("CSFM_SECRET_KEY", ""))
    # Fernet key (urlsafe base64, 32 bytes) used to encrypt stored firewall backups.
    backup_encryption_key: str = field(
        default_factory=lambda: os.environ.get("CSFM_BACKUP_ENCRYPTION_KEY", "")
    )
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("CSFM_DATA_DIR", "/var/lib/comsense"))
    )
    # Public URL of this server, shown to admins when they create enrollment keys.
    public_url: str = field(
        default_factory=lambda: os.environ.get("CSFM_PUBLIC_URL", "https://comsense.example.com")
    )
    # Set to false only for local development over plain HTTP.
    secure_cookies: bool = field(default_factory=lambda: _bool("CSFM_SECURE_COOKIES", True))
    session_max_age: int = field(default_factory=lambda: _int("CSFM_SESSION_MAX_AGE", 8 * 3600))

    # Agent behaviour.
    checkin_interval: int = field(default_factory=lambda: _int("CSFM_CHECKIN_INTERVAL", 60))
    offline_after: int = field(default_factory=lambda: _int("CSFM_OFFLINE_AFTER", 300))
    max_backup_bytes: int = field(
        default_factory=lambda: _int("CSFM_MAX_BACKUP_BYTES", 32 * 1024 * 1024)
    )

    # Housekeeping.
    metrics_retention_days: int = field(
        default_factory=lambda: _int("CSFM_METRICS_RETENTION_DAYS", 30)
    )
    backup_retention_count: int = field(
        default_factory=lambda: _int("CSFM_BACKUP_RETENTION_COUNT", 100)
    )
    scheduled_backup_hours: int = field(
        default_factory=lambda: _int("CSFM_SCHEDULED_BACKUP_HOURS", 24)
    )
    run_scheduler: bool = field(default_factory=lambda: _bool("CSFM_RUN_SCHEDULER", True))

    # Bootstrap admin, created on first start when no users exist.
    initial_admin_user: str = field(
        default_factory=lambda: os.environ.get("CSFM_INITIAL_ADMIN_USER", "admin")
    )
    initial_admin_password: str = field(
        default_factory=lambda: os.environ.get("CSFM_INITIAL_ADMIN_PASSWORD", "")
    )

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    def validate(self) -> None:
        problems = []
        if len(self.secret_key) < 32:
            problems.append("CSFM_SECRET_KEY must be at least 32 characters")
        if not self.backup_encryption_key:
            problems.append("CSFM_BACKUP_ENCRYPTION_KEY is required (generate with `comsense-keygen`)")
        if problems:
            raise RuntimeError("Invalid configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()
