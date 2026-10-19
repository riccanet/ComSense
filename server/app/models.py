from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


class Role(str, enum.Enum):
    admin = "admin"  # everything, including users and enrollment keys
    operator = "operator"  # manage devices, policies, backups
    viewer = "viewer"  # read-only


class DeviceStatus(str, enum.Enum):
    pending = "pending"  # enrolled, waiting for admin approval
    online = "online"
    offline = "offline"
    disabled = "disabled"  # admin disabled; agent calls are rejected


class TaskStatus(str, enum.Enum):
    pending = "pending"  # queued on the server
    sent = "sent"  # handed to the agent in a check-in response
    running = "running"  # agent reported it is still working (e.g. upgrade)
    success = "success"
    failed = "failed"
    cancelled = "cancelled"
    expired = "expired"


class TaskType(str, enum.Enum):
    backup = "backup"
    apply_policy = "apply_policy"
    remove_policy = "remove_policy"
    check_updates = "check_updates"
    upgrade_system = "upgrade_system"
    install_package = "install_package"
    remove_package = "remove_package"
    upgrade_packages = "upgrade_packages"
    restart_service = "restart_service"
    restore_backup = "restore_backup"
    reboot = "reboot"
    refresh_inventory = "refresh_inventory"
    update_agent = "update_agent"
    open_terminal = "open_terminal"
    # Single changes from the firewall's page (names fit the existing 16-character column).
    nat_add = "nat_add"
    nat_remove = "nat_remove"
    nat_edit = "nat_edit"
    alias_add = "alias_add"
    alias_edit = "alias_edit"
    alias_remove = "alias_remove"
    notifications = "notifications"


class PolicyType(str, enum.Enum):
    aliases = "aliases"
    firewall_rules = "firewall_rules"
    system = "system"
    packages = "packages"
    config_set = "config_set"
    port_forward = "port_forward"  # inbound NAT (fits the existing 14-character column)
    notifications = "notifications"  # pfSense email notifications on/off


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False), default=Role.viewer)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    email: Mapped[str] = mapped_column(String(255), default="", server_default="")
    # Receive alert emails (when alert email is turned on in Settings).
    email_alerts: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Set for generated or admin-assigned passwords; the user must choose a new one on first use.
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Two-factor sign-in (services/mfa.py). The TOTP secret is encrypted with CSFM_SECRET_KEY.
    totp_secret: Mapped[str] = mapped_column(String(255), default="", server_default="")
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Last TOTP time step accepted, so a code cannot be used twice.
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    mfa_email_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Hashes of unused one-time recovery codes.
    recovery_codes: Mapped[list[str] | None] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Organization(Base):
    """A customer (shown as "Customers" in the console). A customer can have many firewalls;
    enrollment keys place new firewalls straight into one."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    contact_name: Mapped[str] = mapped_column(String(128), default="", server_default="")
    contact_email: Mapped[str] = mapped_column(String(255), default="", server_default="")
    contact_phone: Mapped[str] = mapped_column(String(64), default="", server_default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    devices: Mapped[list[Device]] = relationship(back_populates="organization")


class EnrollmentKey(Base):
    __tablename__ = "enrollment_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    # First characters of the key, shown in the UI so admins can tell keys apart.
    prefix: Mapped[str] = mapped_column(String(16), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_uses: Mapped[int | None] = mapped_column(Integer)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    require_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organization: Mapped[Organization | None] = relationship()

    def usable(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        if self.revoked:
            return False
        if self.expires_at is not None and aware(self.expires_at) <= now:
            return False
        if self.max_uses is not None and self.use_count >= self.max_uses:
            return False
        return True


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(128))
    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id"), index=True)
    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus, native_enum=False), default=DeviceStatus.online
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_rotated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # pfSense's own hardware identifier (system_get_uniqueid / Netgate Device ID).
    unique_id: Mapped[str] = mapped_column(String(128), default="", index=True)

    hostname: Mapped[str] = mapped_column(String(255), default="")
    edition: Mapped[str] = mapped_column(String(32), default="")  # "ce" or "plus"
    product_version: Mapped[str] = mapped_column(String(64), default="")
    agent_version: Mapped[str] = mapped_column(String(32), default="")
    platform: Mapped[str] = mapped_column(String(128), default="")
    # CPU architecture as the firewall reports it (uname -m): amd64, arm64, arm…
    arch: Mapped[str] = mapped_column(String(32), default="", server_default="")
    serial: Mapped[str] = mapped_column(String(128), default="")
    wan_ip: Mapped[str] = mapped_column(String(64), default="")
    last_seen_ip: Mapped[str] = mapped_column(String(64), default="")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    enrollment_key_id: Mapped[int | None] = mapped_column(ForeignKey("enrollment_keys.id"))

    # Latest full snapshot reported by the agent (interfaces, gateways, services, ...).
    inventory: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Latest update information: {"installed": ..., "available": ..., "packages": [...]}
    updates: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Policy hashes the agent reports as applied: {"<policy id>": "<sha256>"}
    applied_policies: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Policy changes the agent rolled back because the firewall lost contact afterwards:
    # {"<policy id>": "<sha256 of the rolled-back revision>" or "remove"}. Not re-sent until cleared.
    rolled_back_policies: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=dict)
    # Actions the firewall owner allowed locally in the package settings.
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    config_sha256: Mapped[str] = mapped_column(String(64), default="")
    # Last time the agent uploaded its config, even when it matched a stored backup.
    last_backup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str] = mapped_column(Text, default="")

    organization: Mapped[Organization | None] = relationship(back_populates="devices")
    tasks: Mapped[list[Task]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="Task.id.desc()"
    )
    backups: Mapped[list[Backup]] = relationship(
        back_populates="device", cascade="all, delete-orphan", order_by="Backup.id.desc()"
    )
    metrics: Mapped[list[Metric]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    policy_assignments: Mapped[list[PolicyAssignment]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    alerts: Mapped[list[Alert]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )

    @property
    def display_status(self) -> str:
        return self.status.value


class Metric(Base):
    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    cpu_pct: Mapped[float | None]
    mem_pct: Mapped[float | None]
    disk_pct: Mapped[float | None]
    load1: Mapped[float | None]
    states: Mapped[int | None]
    states_max: Mapped[int | None]
    uptime: Mapped[int | None]

    device: Mapped[Device] = relationship(back_populates="metrics")


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    type: Mapped[TaskType] = mapped_column(Enum(TaskType, native_enum=False))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[TaskStatus] = mapped_column(
        Enum(TaskStatus, native_enum=False), default=TaskStatus.pending, index=True
    )
    created_by: Mapped[str] = mapped_column(String(64), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Tasks not picked up before this time expire instead of running late.
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    output: Mapped[str] = mapped_column(Text, default="")

    device: Mapped[Device] = relationship(back_populates="tasks")


class Backup(Base):
    __tablename__ = "backups"
    __table_args__ = (UniqueConstraint("device_id", "sha256", name="uq_backup_device_sha"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    # Path relative to Settings.backup_dir. Contents are Fernet-encrypted gzip.
    path: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(64), default="")
    config_revision: Mapped[str] = mapped_column(String(255), default="")
    product_version: Mapped[str] = mapped_column(String(64), default="")
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    task_id: Mapped[int | None] = mapped_column(ForeignKey("tasks.id", ondelete="SET NULL"))

    device: Mapped[Device] = relationship(back_populates="backups")


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    type: Mapped[PolicyType] = mapped_column(Enum(PolicyType, native_enum=False))
    description: Mapped[str] = mapped_column(Text, default="")
    # Type-specific document; validated by services.policies.validate_policy.
    content: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="")

    assignments: Mapped[list[PolicyAssignment]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


device_group_members = Table(
    "device_group_members",
    Base.metadata,
    Column("group_id", ForeignKey("device_groups.id", ondelete="CASCADE"), primary_key=True),
    Column("device_id", ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True),
)


class DeviceGroup(Base):
    """A named set of firewalls (any customers) that configurations can be assigned to."""

    __tablename__ = "device_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    devices: Mapped[list[Device]] = relationship(secondary=device_group_members, order_by="Device.name")


class PolicyAssignment(Base):
    """Assigns a policy to one device, a firewall group, every device of an organization, or all."""

    __tablename__ = "policy_assignments"
    __table_args__ = (
        UniqueConstraint("policy_id", "device_id", "organization_id", name="uq_policy_target"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[str | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    organization_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE")
    )
    group_id: Mapped[int | None] = mapped_column(ForeignKey("device_groups.id", ondelete="CASCADE"))
    # Applies to every device regardless of organization.
    all_devices: Mapped[bool] = mapped_column(Boolean, default=False)

    policy: Mapped[Policy] = relationship(back_populates="assignments")
    device: Mapped[Device | None] = relationship(back_populates="policy_assignments")
    organization: Mapped[Organization | None] = relationship()
    group: Mapped[DeviceGroup | None] = relationship()


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    # Stable key so the same condition is not raised twice, e.g. "offline" or "gateway:WAN_DHCP".
    key: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16), default="warning")
    message: Mapped[str] = mapped_column(Text)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str] = mapped_column(String(64), default="")
    # When the alert was included in an email, and when its resolution was.
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    device: Mapped[Device] = relationship(back_populates="alerts")


class AppSetting(Base):
    """Server settings edited in the web console (Settings page), stored as JSON per key."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_ip: Mapped[str] = mapped_column(String(64), default="")


class SsoProvider(Base):
    """A SAML 2.0 identity provider users can sign in with (Settings > Single sign-on).
    The provider enforces its own MFA, so a sign-in through it counts as two-factor."""

    __tablename__ = "sso_providers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # google, entra, duo or saml (only changes the setup help and defaults).
    kind: Mapped[str] = mapped_column(String(16), default="saml")
    name: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    idp_entity_id: Mapped[str] = mapped_column(String(512), default="")
    idp_sso_url: Mapped[str] = mapped_column(String(1024), default="")
    # PEM certificate(s) the provider signs with; a new one can be added before the old expires.
    idp_cert: Mapped[str] = mapped_column(Text, default="")
    # Attribute holding the email address; empty: the NameID.
    email_attribute: Mapped[str] = mapped_column(String(255), default="")
    # Create a ComSense user on first sign-in (else only existing users, matched by email, can sign in).
    auto_create: Mapped[bool] = mapped_column(Boolean, default=False)
    default_role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False), default=Role.viewer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TerminalStatus(str, enum.Enum):
    approved = "approved"  # the admin's authenticator code was accepted; waiting for both ends
    connected = "connected"
    closed = "closed"


class TerminalSession(Base):
    """A remote root shell on a firewall (services/terminal.py). Each one is approved with the
    admin's authenticator code and recorded; the recording is replayable from the device page."""

    __tablename__ = "terminal_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    username: Mapped[str] = mapped_column(String(64))
    status: Mapped[TerminalStatus] = mapped_column(
        Enum(TerminalStatus, native_enum=False), default=TerminalStatus.approved
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    close_reason: Mapped[str] = mapped_column(String(255), default="")
    browser_ip: Mapped[str] = mapped_column(String(64), default="")
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)
    bytes_out: Mapped[int] = mapped_column(Integer, default=0)
    # Recording of the terminal output, relative to Settings.data_dir / "terminal".
    recording: Mapped[str] = mapped_column(String(255), default="")

    device: Mapped[Device] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64))  # username or "system" (older entries: "agent:<device id>")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")


def aware(dt: datetime) -> datetime:
    # SQLite drops tzinfo; treat naive values as UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

