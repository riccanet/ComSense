"""Settings edited on the console's Settings page and stored in the database.

Keeping these out of the environment means the container needs only its
bootstrap variables (database, keys, URLs); everything an admin tunes day to
day lives here. Secrets in these settings (the SMTP password) are encrypted
with a key derived from CSFM_SECRET_KEY.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
from dataclasses import asdict, dataclass, field, fields
from typing import Any
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from ..config import Settings
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
    # Address firewalls connect to (https://host:port), put into new enrollment codes.
    # Empty: the default from CSFM_AGENT_URL / the console's host name.
    agent_url: str = ""


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


def normalize_agent_url(value: str, default_port: int) -> str:
    """Turn 'host', 'host:port' or 'https://host[:port]' into 'https://host:port'. Empty stays empty."""
    value = value.strip().rstrip("/")
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ValueError("Firewalls only connect over HTTPS")
    if parts.path or parts.query or parts.fragment or parts.username or parts.password:
        raise ValueError("Enter only a host name and an optional port")
    host = parts.hostname or ""
    try:
        port = parts.port or default_port
    except ValueError:
        raise ValueError("Port must be a number from 1 to 65535") from None
    try:
        ip = ipaddress.ip_address(host)
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        labels = host.split(".")
        if not host or len(host) > 253 or not all(
            label and len(label) <= 63 and label.replace("-", "").isalnum() and not label.startswith("-")
            for label in labels
        ):
            raise ValueError(f"Not a valid host name: {host or value}") from None
    return f"https://{host}:{port}"


def effective_agent_url(db: Session, settings: Settings) -> str:
    """Address firewalls use: the Settings page value, else the environment default."""
    return get_agent_network_settings(db).agent_url or settings.agent_url
