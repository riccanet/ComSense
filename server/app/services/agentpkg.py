"""Build the pfSense agent package (pfSense-pkg-ComSense-<version>.pkg) on the server.

The agent is PHP and shell only, so the package is just an archive: the same
layout `pkg create` writes (see agent/build-pkg.sh), built here so every
install serves a package that matches its own version without a FreeBSD
build host. The archive is a tar (xz compressed) whose first members are
+COMPACT_MANIFEST and +MANIFEST (JSON, which is valid UCL), followed by the
files under their absolute paths. The ABI is "FreeBSD:*", which pkg matches
with fnmatch, so one package installs on pfSense CE and Plus alike.

The output is byte-for-byte reproducible, so it is rebuilt only when the
agent sources change. A package an admin copies into the downloads folder
under the same name is left alone.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import lzma
import re
import tarfile
from pathlib import Path

log = logging.getLogger("comsense.agentpkg")

NAME = "pfSense-pkg-ComSense"
ABI = "FreeBSD:*"
MARKER = ".generated"
# Fixed timestamp for the archived files, so builds are reproducible.
MTIME = 1767225600  # 2026-01-01
_HERE = Path(__file__).resolve()

# Source file (relative to files/) -> installed path and mode, as in build-pkg.sh.
_FILES = [
    ("usr/local/pkg/comsense.xml", 0o644),
    ("usr/local/pkg/comsense.inc", 0o644),
    ("usr/local/pkg/comsense/agent.php", 0o644),
    ("usr/local/pkg/comsense/lib/*.inc", 0o644),
    ("usr/local/sbin/comsense-agentd", 0o755),
    ("usr/local/www/comsense_status.php", 0o644),
    ("etc/inc/priv/comsense.priv.inc", 0o644),
    (f"usr/local/share/{NAME}/info.xml", 0o644),
]


def find_port_dir() -> Path | None:
    """agent/pfSense-pkg-ComSense next to the server code (the image's /app, or a git checkout)."""
    for base in (_HERE.parents[2], _HERE.parents[3]):
        candidate = base / "agent" / NAME
        if (candidate / "Makefile").is_file():
            return candidate
    return None


def port_version(port: Path) -> str:
    m = re.search(r"^PORTVERSION=\s*(\S+)", (port / "Makefile").read_text(), re.M)
    if not m:
        raise ValueError("PORTVERSION not found in the port Makefile")
    return m.group(1)


def _script(port: Path, name: str, phase: str) -> str:
    text = (port / "files" / name).read_text().replace("%%PORTNAME%%", NAME)
    lines = text.splitlines()[1:]  # drop the #! line, as pkg runs it with sh
    return "\n".join(lines).replace("${2}", phase) + "\n"


def build_package(port: Path) -> tuple[str, bytes]:
    """Return (file name, package bytes)."""
    version = port_version(port)
    files_dir = port / "files"
    entries: list[tuple[str, bytes, int]] = []
    for pattern, mode in _FILES:
        matches = sorted(files_dir.glob(pattern))
        if not matches:
            raise FileNotFoundError(f"agent source missing: {pattern}")
        for src in matches:
            data = src.read_bytes()
            if src.name in ("info.xml", "comsense.xml"):
                data = data.replace(b"%%PKGVERSION%%", version.encode())
            entries.append(("/" + src.relative_to(files_dir).as_posix(), data, mode))
    entries.sort()

    manifest = {
        "name": NAME,
        "origin": f"sysutils/{NAME}",
        "version": version,
        "comment": "ComSense Firewall Manager agent for pfSense",
        "maintainer": "https://github.com/riccanet/ComSense/issues",
        "www": "https://github.com/riccanet/ComSense",
        "abi": ABI,
        "arch": ABI,
        "prefix": "/",
        "flatsize": sum(len(d) for _, d, _ in entries),
        "licenselogic": "single",
        "licenses": ["APACHE20"],
        "desc": (port / "pkg-descr").read_text().strip(),
        "categories": ["sysutils"],
    }
    compact = json.dumps(manifest, separators=(",", ":")).encode()
    full = dict(
        manifest,
        files={path: "1$" + hashlib.sha256(data).hexdigest() for path, data, _ in entries},
        scripts={
            "post-install": _script(port, "pkg-install.in", "POST-INSTALL"),
            "pre-deinstall": _script(port, "pkg-deinstall.in", "DEINSTALL"),
        },
    )
    full_json = json.dumps(full, separators=(",", ":")).encode()

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path, data, mode in [("+COMPACT_MANIFEST", compact, 0o644), ("+MANIFEST", full_json, 0o644), *entries]:
            info = tarfile.TarInfo(path)
            info.size, info.mode, info.mtime = len(data), mode, MTIME
            info.uname, info.gname, info.uid, info.gid = "root", "wheel", 0, 0
            tar.addfile(info, io.BytesIO(data))
    return f"{NAME}-{version}.pkg", lzma.compress(raw.getvalue(), preset=6)


def ensure_package(downloads: Path) -> Path | None:
    """Write the package into downloads/ if it is missing or out of date; return its path."""
    port = find_port_dir()
    if port is None:
        return None
    try:
        name, data = build_package(port)
    except (OSError, ValueError) as exc:
        log.warning("Could not build the agent package: %s", exc)
        return None
    target = downloads / name
    marker = downloads / MARKER
    digest = hashlib.sha256(data).hexdigest()
    ours = marker.is_file() and name in marker.read_text().split()
    if target.exists() and not ours:
        return target  # placed there by an admin
    if not target.exists() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        downloads.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(target)
        marker.write_text(name + "\n")
        log.info("Built agent package %s (sha256 %s)", name, digest)
    return target


def latest_package(downloads: Path) -> dict[str, str] | None:
    """Newest package in downloads/ as {name, sha256}, or None."""
    packages = sorted(downloads.glob(f"{NAME}-*.pkg"), key=lambda p: p.stat().st_mtime)
    if not packages:
        return None
    latest = packages[-1]
    return {"name": latest.name, "sha256": hashlib.sha256(latest.read_bytes()).hexdigest()}
