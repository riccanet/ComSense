"""Settings edited on the console's Settings page and stored in the database.

Keeping these out of the environment means the container needs only its
bootstrap variables (database, keys, URLs); everything an admin tunes day to
day lives here. Secrets in these settings (the SMTP password) are encrypted
with a key derived from CSFM_SECRET_KEY.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import asdict, dataclass, field, fields
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from ..models import AppSetting, utcnow

EMAIL_KEY = "email"
ALERT_EMAIL_KEY = "alert_email"
AGENT_NETWORK_KEY = "agent_network"
SMTP_SECURITY = ("starttls", "ssl", "none")
SEVERITIES = ("warning", "critical")


@dataclass
class EmailSettings:
    enabled: bool = False
    host: str = ""
    port: int = 587
    security: str = "starttls"  # one of SMTP_SECURITY
    username: str = ""
    password_encrypted: str = ""
    from_address: str = ""
    from_name: str = "ComSense Firewall Manager"

    @property
    def configured(self) -> bool:
        return self.enabled and bool(self.host) and bool(self.from_address)


@dataclass
class AlertEmailSettings:
    enabled: bool = False
    # Lowest severity that is emailed: "warning" sends everything, "critical" only critical alerts.
    min_severity: str = "warning"
    notify_resolved: bool = True
    # Addresses that get alerts in addition to users who opted in (e.g. a NOC mailbox).
    extra_recipients: list[str] = field(default_factory=list)
    # Alerts opened before alert email was switched on are never sent.
    enabled_since: str = ""


@dataclass
class AgentNetworkSettings:
    # Networks allowed to send a PROXY protocol header on the agent port (CIDRs),
    # e.g. a NetBird or HAProxy pass-through proxy. Empty: headers are refused.
    trusted_proxies: list[str] = field(default_factory=list)


def _secret_box(secret_key: str) -> Fernet:
    digest = hashlib.sha256(b"comsense-settings:" + secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(secret_key: str, value: str) -> str:
    return _secret_box(secret_key).encrypt(value.encode()).decode() if value else ""


def decrypt_secret(secret_key: str, value: str) -> str:
    if not value:
        return ""
    try:
        return _secret_box(secret_key).decrypt(value.encode()).decode()
    except InvalidToken:
        # CSFM_SECRET_KEY changed since the password was saved; it must be entered again.
        return ""


def _load(db: Session, key: str, cls):
    row = db.get(AppSetting, key)
    data: dict[str, Any] = row.value if row else {}
    known = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in known})


def _save(db: Session, key: str, obj, actor: str) -> None:
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key)
        db.add(row)
    row.value = asdict(obj)
    row.updated_at = utcnow()
    row.updated_by = actor


def get_email_settings(db: Session) -> EmailSettings:
    return _load(db, EMAIL_KEY, EmailSettings)


def save_email_settings(db: Session, value: EmailSettings, actor: str) -> None:
    _save(db, EMAIL_KEY, value, actor)


def get_alert_email_settings(db: Session) -> AlertEmailSettings:
    return _load(db, ALERT_EMAIL_KEY, AlertEmailSettings)


def save_alert_email_settings(db: Session, value: AlertEmailSettings, actor: str) -> None:
    _save(db, ALERT_EMAIL_KEY, value, actor)


def get_agent_network_settings(db: Session) -> AgentNetworkSettings:
    return _load(db, AGENT_NETWORK_KEY, AgentNetworkSettings)


def save_agent_network_settings(db: Session, value: AgentNetworkSettings, actor: str) -> None:
    _save(db, AGENT_NETWORK_KEY, value, actor)
