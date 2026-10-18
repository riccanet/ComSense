"""Outgoing email over SMTP, configured on the Settings page."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from .appsettings import EmailSettings, decrypt_secret

SMTP_TIMEOUT = 20


class MailError(RuntimeError):
    pass


def build_message(
    cfg: EmailSettings, to: list[str], subject: str, text: str, html: str | None = None
) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((cfg.from_name, cfg.from_address)) if cfg.from_name else cfg.from_address
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=cfg.from_address.rpartition("@")[2] or None)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    return msg


def deliver(cfg: EmailSettings, password: str, msg: EmailMessage) -> None:
    """Send one message. Raises MailError with a readable reason on failure."""
    context = ssl.create_default_context()
    try:
        if cfg.security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=SMTP_TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=SMTP_TIMEOUT)
        with server:
            server.ehlo()
            if cfg.security == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if cfg.username:
                server.login(cfg.username, password)
            server.send_message(msg)
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise MailError(f"{type(exc).__name__}: {exc}") from exc


def send_mail(
    cfg: EmailSettings,
    secret_key: str,
    to: list[str],
    subject: str,
    text: str,
    html: str | None = None,
) -> None:
    if not cfg.configured:
        raise MailError("Email is not set up. An admin can configure it under Settings.")
    recipients = [r for r in dict.fromkeys(a.strip() for a in to) if r]
    if not recipients:
        raise MailError("No recipients")
    password = decrypt_secret(secret_key, cfg.password_encrypted)
    if cfg.username and cfg.password_encrypted and not password:
        raise MailError("The saved SMTP password can no longer be read; enter it again under Settings.")
    deliver(cfg, password, build_message(cfg, recipients, subject, text, html))
