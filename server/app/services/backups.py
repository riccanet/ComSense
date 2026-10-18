"""Encrypted storage for pfSense config.xml backups."""
from __future__ import annotations

import gzip
import hashlib
import io
import re
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Backup, Device, utcnow
from ..security import BackupCipher

_REVISION_RE = re.compile(
    rb"<revision>.*?<description>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>", re.S
)
_VERSION_RE = re.compile(rb"<version>([0-9.]+)</version>")


class BackupError(ValueError):
    pass


def _gunzip_limited(data: bytes, limit: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as fh:
            raw = fh.read(limit + 1)
    except (OSError, EOFError) as exc:
        raise BackupError("Backup is not valid gzip data") from exc
    if len(raw) > limit:
        raise BackupError("Backup exceeds the maximum allowed size")
    return raw


def inspect_config(xml: bytes) -> dict[str, str]:
    head = xml[:4096].lstrip()
    if not head.startswith(b"<?xml") or b"<pfsense>" not in xml[:8192]:
        raise BackupError("Backup does not look like a pfSense config.xml")
    if b"</pfsense>" not in xml[-4096:]:
        raise BackupError("Backup is truncated")
    info = {"revision": "", "config_version": ""}
    m = _REVISION_RE.search(xml[:200_000])
    if m:
        info["revision"] = m.group(1).decode("utf-8", "replace")[:255]
    m = _VERSION_RE.search(xml[:4096])
    if m:
        info["config_version"] = m.group(1).decode()
    return info


def store_backup(
    db: Session,
    settings: Settings,
    device: Device,
    gz_payload: bytes,
    claimed_sha256: str,
    reason: str,
    task_id: int | None = None,
) -> tuple[Backup, bool]:
    """Validate and store a gzip-compressed config.xml. Returns (backup, created)."""
    if len(gz_payload) > settings.max_backup_bytes:
        raise BackupError("Backup exceeds the maximum allowed size")
    xml = _gunzip_limited(gz_payload, settings.max_backup_bytes)
    digest = hashlib.sha256(xml).hexdigest()
    if claimed_sha256 and claimed_sha256.lower() != digest:
        raise BackupError("Checksum mismatch; upload was corrupted")
    info = inspect_config(xml)

    existing = db.scalar(select(Backup).where(Backup.device_id == device.id, Backup.sha256 == digest))
    device.config_sha256 = digest
    if existing is not None:
        return existing, False

    cipher = BackupCipher(settings.backup_encryption_key)
    now = utcnow()
    rel = Path(device.id) / f"{now:%Y%m%dT%H%M%SZ}_{digest[:12]}.xml.gz.enc"
    dest = settings.backup_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = dest.with_suffix(".tmp")
    tmp.write_bytes(cipher.encrypt(gzip.compress(xml)))
    tmp.chmod(0o600)
    tmp.replace(dest)

    backup = Backup(
        device_id=device.id,
        created_at=now,
        sha256=digest,
        size=len(xml),
        path=str(rel),
        reason=reason[:64],
        config_revision=info["revision"],
        product_version=device.product_version,
        task_id=task_id,
    )
    db.add(backup)
    return backup, True


def load_backup(settings: Settings, backup: Backup) -> bytes:
    """Return the decrypted, decompressed config.xml."""
    path = (settings.backup_dir / backup.path).resolve()
    if settings.backup_dir.resolve() not in path.parents:
        raise BackupError("Invalid backup path")
    cipher = BackupCipher(settings.backup_encryption_key)
    return gzip.decompress(cipher.decrypt(path.read_bytes()))


def delete_backup_file(settings: Settings, backup: Backup) -> None:
    path = settings.backup_dir / backup.path
    path.unlink(missing_ok=True)


def prune_backups(db: Session, settings: Settings, device: Device) -> int:
    keep = settings.backup_retention_count
    stmt = (
        select(Backup)
        .where(Backup.device_id == device.id, Backup.pinned.is_(False))
        .order_by(Backup.created_at.desc())
        .offset(keep)
    )
    removed = 0
    for backup in db.scalars(stmt):
        delete_backup_file(settings, backup)
        db.delete(backup)
        removed += 1
    return removed
