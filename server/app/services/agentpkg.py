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
PACKAGE_RE = re.compile(rf"{NAME}-(\d+(?:\.\d+)*(?:[._-][0-9A-Za-z]+)*)\.pkg")
# File timestamps come from each file's content: identical builds stay byte-for-byte identical,
# while a changed file gets a new timestamp. That matters on pfSense, whose web server PHP caches
# compiled files (opcache) and only reloads one whose timestamp changed; a fixed timestamp kept the
# GUI on the previous version's code after an upgrade. All values fall within 2025, in the past.
MTIME_BASE = 1735689600  # 2025-01-01
MTIME_SPAN = 365 * 86400


def _mtime(data: bytes) -> int:
    return MTIME_BASE + int.from_bytes(hashlib.sha256(data).digest()[:8], "big") % MTIME_SPAN
_HERE = Path(__file__).resolve()

# Source file (relative to files/) -> installed path and mode, as in build-pkg.sh.
_FILES = [
    ("usr/local/pkg/comsense.xml", 0o644),
    ("usr/local/pkg/comsense.inc", 0o644),
    ("usr/local/pkg/comsense/agent.php", 0o644),
    ("usr/local/pkg/comsense/lib/*.inc", 0o644),
    ("usr/local/sbin/comsense-agentd", 0o755),
    ("usr/local/sbin/comsense-watchdogd", 0o755),
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
        # pfSense's Installed Packages page only lists packages whose repository (pkg query %R) is
        # "pfSense"; a file added with pkg add would otherwise show as "unknown-repository" and stay
        # hidden. pkg keeps this annotation for local installs, so the package appears there and can
        # be removed from the GUI like any other.
        "annotations": {"repository": "pfSense"},
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
            info.size, info.mode, info.mtime = len(data), mode, _mtime(data)
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


# ------------------------------------------------------------------ bootstrap for agents up to 0.2.9

# Agents before this version install an update with a plain `pkg add`, which pkg (up to 2.1, every
# pfSense release so far) refuses over an installed package. They are sent a bootstrap package instead:
# another package (so `pkg add` takes it) holding the real one, whose install script installs that with
# `pkg add -f` in the background, removes itself and restarts the agent.
BOOTSTRAP_BELOW = "0.2.10"
BOOTSTRAP_NAME = "comsense-agent-bootstrap"
BOOTSTRAP_DIR = "/usr/local/share/comsense-agent-bootstrap"
# The old agent counts an update as still installing while a process mentions agent-update.pkg
# (pgrep -f), so the background job carries that name in its command line from start to end.
_BOOTSTRAP_JOB = (
    "sleep 3; i=0; "
    "while [ $i -lt 300 ] && { /bin/pgrep -q -x pkg-static || /bin/pgrep -q -x pkg; }; do sleep 2; i=$((i+1)); done; "
    "LOG=/var/db/comsense/agent-update.log; "
    "echo \"Bootstrap: installing the agent with pkg add -f\" >> $LOG; "
    "/usr/local/sbin/pkg-static add -f " + BOOTSTRAP_DIR + "/agent-update.pkg >> $LOG 2>&1; "
    "/usr/local/sbin/pkg-static delete -y " + BOOTSTRAP_NAME + " >> $LOG 2>&1; "
    "touch /var/db/comsense/checkin-now; "
    "/usr/local/etc/rc.d/comsense.sh restart >> $LOG 2>&1"
)
BOOTSTRAP_SCRIPT = "/usr/sbin/daemon -f /bin/sh -c '" + _BOOTSTRAP_JOB + "'\n"


def needs_bootstrap(agent_version: str | None) -> bool:
    return bool(agent_version) and agent_outdated(agent_version, BOOTSTRAP_BELOW)


def build_bootstrap(real: bytes, version: str) -> bytes:
    """The bootstrap package carrying `real` (a built agent package of `version`)."""
    path = f"{BOOTSTRAP_DIR}/agent-update.pkg"
    manifest = {
        "name": BOOTSTRAP_NAME,
        "origin": f"sysutils/{BOOTSTRAP_NAME}",
        "version": version,
        "comment": "Installs the ComSense agent over an older one, then removes itself",
        "maintainer": "https://github.com/riccanet/ComSense/issues",
        "www": "https://github.com/riccanet/ComSense",
        "abi": ABI,
        "arch": ABI,
        "prefix": "/",
        "flatsize": len(real),
        "licenselogic": "single",
        "licenses": ["APACHE20"],
        "desc": "Updates the ComSense agent on firewalls whose agent cannot replace itself (0.2.9 and older).",
        "categories": ["sysutils"],
    }
    compact = json.dumps(manifest, separators=(",", ":")).encode()
    full = json.dumps(dict(manifest, files={path: "1$" + hashlib.sha256(real).hexdigest()},
                           scripts={"post-install": BOOTSTRAP_SCRIPT}), separators=(",", ":")).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data, mode in (("+COMPACT_MANIFEST", compact, 0o644), ("+MANIFEST", full, 0o644), (path, real, 0o600)):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, _mtime(data)
            info.uname, info.gname, info.uid, info.gid = "root", "wheel", 0, 0
            tar.addfile(info, io.BytesIO(data))
    return lzma.compress(raw.getvalue(), preset=6)


def bootstrap_package(downloads: Path, package: dict[str, str]) -> Path:
    """downloads/bootstrap/<package name>, built from that package if missing or out of date."""
    real = (downloads / package["name"]).read_bytes()
    data = build_bootstrap(real, package["version"])
    target = downloads / "bootstrap" / package["name"]
    if not target.is_file() or target.read_bytes() != data:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(target)
        log.info("Built bootstrap package for %s (sha256 %s)", package["name"], hashlib.sha256(data).hexdigest())
    return target


def package_for(downloads: Path, package: dict[str, str], agent_version: str | None) -> dict[str, str]:
    """What an update_agent task sends a firewall: the package itself, or the bootstrap for old agents."""
    if not needs_bootstrap(agent_version):
        return package
    path = bootstrap_package(downloads, package)
    return dict(package, sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def _version_key(version: str) -> tuple:
    return tuple(int(p) if p.isdigit() else p for p in re.split(r"[._-]", version))


def latest_package(downloads: Path) -> dict[str, str] | None:
    """Newest package in downloads/ as {name, version, sha256}, or None."""
    packages = []
    for path in downloads.glob(f"{NAME}-*.pkg"):
        m = PACKAGE_RE.fullmatch(path.name)
        if m:
            packages.append((_version_key(m.group(1)), path.stat().st_mtime, m.group(1), path))
    if not packages:
        return None
    _, _, version, latest = max(packages)
    return {"name": latest.name, "version": version, "sha256": hashlib.sha256(latest.read_bytes()).hexdigest()}


def agent_outdated(installed: str, latest: str) -> bool:
    """True if the agent version a firewall reports is older than the one this server serves."""
    if not installed or not latest:
        return False
    try:
        return _version_key(installed) < _version_key(latest)
    except TypeError:  # mixed number/text parts
        return installed != latest
