"""TLS for the agent listener.

Either the operator supplies a certificate (CSFM_AGENT_TLS_CERT / _KEY), or the
server issues its own: a long-lived private key plus a self-signed certificate
that is renewed automatically. Agents trust a self-signed certificate by
pinning the SHA-256 of its public key, which is delivered to them inside the
enrollment code. The key is kept across renewals so the pin never changes.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .config import Settings

log = logging.getLogger("comsense.tls")

CERT_LIFETIME = timedelta(days=825)
RENEW_BEFORE = timedelta(days=30)


@dataclass(frozen=True)
class AgentTLS:
    cert_file: Path
    key_file: Path
    # base64 SHA-256 of the certificate's SubjectPublicKeyInfo, as curl expects after "sha256//".
    pin: str
    # True when the server generated the certificate, so agents must pin it.
    self_signed: bool
    not_after: datetime


def spki_pin(cert: x509.Certificate) -> str:
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def agent_hostnames(settings: Settings, extra: Iterable[str] = ()) -> list[str]:
    names = [urlsplit(settings.agent_url).hostname or "", urlsplit(settings.public_url).hostname or ""]
    names += list(extra)
    names += [n.strip() for n in settings.agent_tls_names.split(",")]
    out: list[str] = []
    for name in names:
        if name and name not in out:
            out.append(name)
    return out or ["localhost"]


def _san(names: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = []
    for name in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def _load_or_create_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        return key
    key = ec.generate_private_key(ec.SECP256R1())
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tmp.chmod(0o600)
    tmp.replace(path)
    return key


def _issue(key: ec.EllipticCurvePrivateKey, names: list[str], now: datetime) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + CERT_LIFETIME)
        .add_extension(_san(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )


def ensure_agent_tls(
    settings: Settings, now: datetime | None = None, extra_names: Iterable[str] = ()
) -> AgentTLS:
    """extra_names: host names from the Settings page (see appsettings.agent_tls_names)."""
    now = now or datetime.now(timezone.utc)
    if settings.agent_tls_cert and settings.agent_tls_key:
        cert_file, key_file = Path(settings.agent_tls_cert), Path(settings.agent_tls_key)
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        return AgentTLS(cert_file, key_file, spki_pin(cert), False, cert.not_valid_after_utc)

    tls_dir = settings.data_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_file, cert_file = tls_dir / "agent.key", tls_dir / "agent.pem"
    key = _load_or_create_key(key_file)
    names = agent_hostnames(settings, extra_names)

    cert = x509.load_pem_x509_certificate(cert_file.read_bytes()) if cert_file.exists() else None
    stale = (
        cert is None
        or cert.not_valid_after_utc - now < RENEW_BEFORE
        or cert.public_key().public_numbers() != key.public_key().public_numbers()
        or set(names) != _cert_names(cert)
    )
    if stale:
        cert = _issue(key, names, now)
        tmp = cert_file.with_suffix(".tmp")
        tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        tmp.replace(cert_file)
        log.info("Issued agent TLS certificate for %s (valid until %s)", ", ".join(names), cert.not_valid_after_utc)
    assert cert is not None
    return AgentTLS(cert_file, key_file, spki_pin(cert), True, cert.not_valid_after_utc)


def _cert_names(cert: x509.Certificate) -> set[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set()
    return {str(v) for v in san.get_values_for_type(x509.DNSName)} | {
        str(v) for v in san.get_values_for_type(x509.IPAddress)
    }
