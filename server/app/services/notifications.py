"""Alert emails and password reset links."""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta
from html import escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Alert, PasswordResetToken, User, aware, utcnow
from ..security import hash_secret
from .alerts import category_of
from .appsettings import (
    effective_console_url,
    format_dt,
    get_alert_category_settings,
    get_alert_email_settings,
    get_email_settings,
)
from .mailer import MailError, send_mail

log = logging.getLogger("comsense.notifications")

RESET_TOKEN_TTL = timedelta(hours=1)
SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


def _where(alert: Alert) -> str:
    """'Customer / firewall', so recipients see which client is affected."""
    org = alert.device.organization
    return f"{org.name} / {alert.device.name}" if org else alert.device.name


def _fmt(dt: datetime | None) -> str:
    return format_dt(dt)


def _html_page(title: str, body_html: str) -> str:
    return f"""<!doctype html><html><body style="margin:0;background:#f5f6f8;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:#1d2430">
<div style="max-width:620px;margin:24px auto;background:#fff;border:1px solid #dde2ea;border-top:3px solid #d7262e;border-radius:8px;padding:20px 24px">
<div style="font-weight:800;font-size:18px">ComSense <span style="font-weight:400;color:#667085">Firewall Manager</span></div>
<h1 style="font-size:18px;margin:16px 0 12px">{escape(title)}</h1>
{body_html}
</div></body></html>"""


# --------------------------------------------------------------------- alerts


def alert_recipients(db: Session, extra: list[str]) -> list[str]:
    users = db.scalars(
        select(User).where(User.active.is_(True), User.email_alerts.is_(True), User.email != "")
    )
    return list(dict.fromkeys([u.email for u in users] + [e for e in extra if e]))


def send_alert_notifications(db: Session, settings: Settings) -> int:
    """Email newly opened, still open and (optionally) resolved alerts as one summary per recipient.

    An alert is emailed when it opens and, if its category repeats, again every repeat_hours while it
    stays open and nobody acknowledged it; once more when it resolves. Categories with email off are
    never emailed. Returns the number of emails sent. The caller commits.
    """
    alert_cfg = get_alert_email_settings(db)
    mail_cfg = get_email_settings(db)
    if not alert_cfg.enabled or not mail_cfg.configured:
        return 0
    categories = get_alert_category_settings(db)
    now = utcnow()
    since = datetime.fromisoformat(alert_cfg.enabled_since) if alert_cfg.enabled_since else now
    min_rank = SEVERITY_RANK.get(alert_cfg.min_severity, 1)

    def emailed(alert: Alert) -> bool:
        return categories.flag(category_of(alert.key), "email")

    opened: list[Alert] = []
    for alert in db.scalars(select(Alert).where(Alert.notified_at.is_(None)).order_by(Alert.opened_at)):
        if (aware(alert.opened_at) < aware(since) or SEVERITY_RANK.get(alert.severity, 1) < min_rank
                or not emailed(alert)):
            # Never emailed, so its resolution is not emailed either.
            alert.notified_at = now
            alert.resolved_notified_at = now
            continue
        opened.append(alert)
    resolved = [
        a
        for a in db.scalars(
            select(Alert).where(
                Alert.resolved_at.is_not(None),
                Alert.resolved_notified_at.is_(None),
                Alert.notified_at.is_not(None),
            )
        )
        if a not in opened
    ]
    if not alert_cfg.notify_resolved:
        resolved_off = resolved
        resolved = []
    else:
        resolved_off = [a for a in resolved if not emailed(a)]
        resolved = [a for a in resolved if emailed(a)]
    for alert in resolved_off:
        alert.resolved_notified_at = now
    reminders = _reminders(db, categories, min_rank, now) if categories.repeat_hours > 0 else []
    if not opened and not resolved and not reminders:
        return 0

    recipients = alert_recipients(db, alert_cfg.extra_recipients)
    if recipients:
        subject, text, html = _alert_digest(
            effective_console_url(db, settings), opened, resolved, reminders, categories.repeat_hours
        )
        sent = 0
        for to in recipients:
            try:
                send_mail(mail_cfg, settings.secret_key, [to], subject, text, html)
                sent += 1
            except MailError as exc:
                log.warning("Alert email to %s failed: %s", to, exc)
        if sent == 0:
            return 0  # leave them pending and retry on the next pass
    for alert in opened:
        alert.notified_at = now
        if alert.resolved_at is not None:
            alert.resolved_notified_at = now
    for alert in resolved:
        alert.resolved_notified_at = now
    for alert in reminders:
        alert.notified_at = now  # the next reminder is due repeat_hours from now
    return len(recipients)


def _reminders(db: Session, categories, min_rank: int, now: datetime) -> list[Alert]:
    """Open, unacknowledged alerts last emailed at least repeat_hours ago, in categories that repeat."""
    due = now - timedelta(hours=categories.repeat_hours)
    stmt = select(Alert).where(
        Alert.resolved_at.is_(None), Alert.acknowledged_by == "", Alert.notified_at.is_not(None),
        Alert.notified_at <= due,
    ).order_by(Alert.opened_at)
    return [
        a for a in db.scalars(stmt)
        if SEVERITY_RANK.get(a.severity, 1) >= min_rank
        and categories.flag(category_of(a.key), "email") and categories.flag(category_of(a.key), "repeat")
    ]


def _alert_digest(console_url: str, opened: list[Alert], resolved: list[Alert],
                  reminders: list[Alert] | None = None, repeat_hours: int = 24) -> tuple[str, str, str]:
    reminders = reminders or []
    parts = []
    if opened:
        parts.append(f"{len(opened)} new alert{'s' if len(opened) != 1 else ''}")
    if reminders:
        parts.append(f"{len(reminders)} still open")
    if resolved:
        parts.append(f"{len(resolved)} resolved")
    critical = any(a.severity == "critical" for a in opened + reminders)
    subject = f"[ComSense]{' CRITICAL:' if critical else ''} {', '.join(parts)}"
    link = f"{console_url}/alerts"

    lines, rows = [], []
    if opened:
        lines.append("New alerts:")
        for a in opened:
            state = f" (resolved {_fmt(a.resolved_at)})" if a.resolved_at else ""
            lines.append(f"  [{a.severity.upper()}] {_where(a)}: {a.message} - since {_fmt(a.opened_at)}{state}")
            color = "#b42318" if a.severity == "critical" else "#a86500"
            rows.append(
                f'<tr><td style="padding:6px 8px;color:{color};font-weight:600">{escape(a.severity)}</td>'
                f'<td style="padding:6px 8px">{escape(_where(a))}</td>'
                f'<td style="padding:6px 8px">{escape(a.message)}{escape(state)}</td>'
                f'<td style="padding:6px 8px;color:#667085">{_fmt(a.opened_at)}</td></tr>'
            )
    if reminders:
        lines.append(f"Still open and not acknowledged (repeated every {repeat_hours} hours until acknowledged):")
        rows.append(
            '<tr><td colspan="4" style="padding:12px 8px 4px;font-weight:600">Still open, not acknowledged'
            f'<span style="font-weight:400;color:#667085"> (repeated every {repeat_hours} hours until acknowledged)'
            "</span></td></tr>"
        )
        for a in reminders:
            lines.append(f"  [{a.severity.upper()}] {_where(a)}: {a.message} - since {_fmt(a.opened_at)}")
            color = "#b42318" if a.severity == "critical" else "#a86500"
            rows.append(
                f'<tr><td style="padding:6px 8px;color:{color};font-weight:600">{escape(a.severity)}</td>'
                f'<td style="padding:6px 8px">{escape(_where(a))}</td>'
                f'<td style="padding:6px 8px">{escape(a.message)}</td>'
                f'<td style="padding:6px 8px;color:#667085">since {_fmt(a.opened_at)}</td></tr>'
            )
    if resolved:
        lines.append("Resolved:")
        for a in resolved:
            lines.append(f"  {_where(a)}: {a.message} - resolved {_fmt(a.resolved_at)}")
            rows.append(
                f'<tr><td style="padding:6px 8px;color:#1b7f4a;font-weight:600">resolved</td>'
                f'<td style="padding:6px 8px">{escape(_where(a))}</td>'
                f'<td style="padding:6px 8px">{escape(a.message)}</td>'
                f'<td style="padding:6px 8px;color:#667085">{_fmt(a.resolved_at)}</td></tr>'
            )
    text = "\n".join(lines) + f"\n\nView alerts: {link}\n"
    html = _html_page(
        ", ".join(parts).capitalize(),
        '<table style="border-collapse:collapse;width:100%;font-size:14px">' + "".join(rows) + "</table>"
        f'<p style="margin-top:16px"><a href="{escape(link)}" style="color:#b81f26">View alerts</a></p>',
    )
    return subject, text, html


# ----------------------------------------------------------- password resets


def create_reset_token(db: Session, user: User, ip: str = "") -> str:
    """Issue a single-use reset token, revoking any earlier unused ones. The caller commits."""
    now = utcnow()
    for old in db.scalars(
        select(PasswordResetToken).where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
    ):
        old.used_at = now
    token = secrets.token_urlsafe(32)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_secret(token),
            expires_at=now + RESET_TOKEN_TTL,
            requested_ip=ip[:64],
        )
    )
    return token


def find_reset_token(db: Session, token: str) -> PasswordResetToken | None:
    row = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_secret(token)))
    if row is None or row.used_at is not None or aware(row.expires_at) < utcnow():
        return None
    return row


def send_reset_email(db: Session, settings: Settings, user: User, token: str, requested_by_admin: bool = False) -> None:
    link = f"{effective_console_url(db, settings)}/reset/{token}"
    who = "An administrator requested" if requested_by_admin else "Someone (hopefully you) requested"
    text = (
        f"Hello {user.username},\n\n{who} a password reset for your ComSense Firewall Manager account.\n\n"
        f"Set a new password here (the link works once and expires in 1 hour):\n{link}\n\n"
        "If you did not expect this, ignore this email; your password stays the same.\n"
    )
    html = _html_page(
        "Reset your password",
        f"<p>Hello {escape(user.username)},</p><p>{escape(who)} a password reset for your account.</p>"
        f'<p><a href="{escape(link)}" style="display:inline-block;background:#d7262e;color:#fff;'
        f'padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:600">Set a new password</a></p>'
        "<p style=\"color:#667085;font-size:13px\">The link works once and expires in 1 hour. "
        "If you did not expect this, ignore this email; your password stays the same.</p>",
    )
    send_mail(get_email_settings(db), settings.secret_key, [user.email], "Reset your ComSense password", text, html)
