from __future__ import annotations

import hashlib
import io
import json
import lzma
import re
import tarfile

from conftest import enroll, login, make_key
from sqlalchemy import select

from app.enrollment import parse_code
from app.models import EnrollmentKey, Organization, Role, User
from app.security import hash_password
from app.services.agentpkg import build_package, ensure_package, find_port_dir
from app.services.appsettings import get_email_settings, get_site_settings


def test_admin_is_sent_to_setup_until_finished(client, db):
    csrf = login(client)
    assert client.get("/", follow_redirects=False).headers["location"] == "/setup"
    page = client.get("/setup").text
    assert "Set up ComSense" in page and 'aria-current="step"' in page

    r = client.post("/setup/finish", data={"skipped": "true", "csrf_token": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert client.get("/", follow_redirects=False).status_code == 200
    db.expire_all()
    assert get_site_settings(db).setup_completed_by == "admin"
    # It can still be opened again from Settings.
    assert client.get("/setup").status_code == 200


def test_no_redirect_once_a_firewall_is_enrolled(client, db, agent):
    login(client)
    enroll(agent, make_key(db))
    assert client.get("/", follow_redirects=False).status_code == 200


def test_setup_is_admin_only(client, db):
    db.add(User(username="viewer1", password_hash=hash_password("viewer-password-1"), role=Role.viewer))
    db.commit()
    login(client, "viewer1", "viewer-password-1")
    assert client.get("/", follow_redirects=False).status_code == 200  # viewers go to the dashboard
    assert client.get("/setup").status_code == 403


def test_wizard_steps_save_settings_and_create_first_code(client, db, settings):
    csrf = login(client)

    # Step 1: addresses; errors stay on the step, success moves on.
    bad = client.post(
        "/settings/agent-network",
        data={"console_url": "http://x", "back": "/setup", "next": "/setup/email", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert bad.headers["location"] == "/setup"
    ok = client.post(
        "/settings/agent-network",
        data={
            "console_url": "console.example.com",
            "agent_url": "agents.example.com",
            "back": "/setup",
            "next": "/setup/email",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert ok.headers["location"] == "/setup/email"
    db.expire_all()
    assert get_site_settings(db).console_url == "https://console.example.com"

    # Step 2: email; the test form appears once it is configured.
    page = client.get("/setup/email").text
    assert "Skip for now" in page and "Send test email" not in page
    r = client.post(
        "/settings/email",
        data={
            "enabled": "true",
            "host": "smtp.example.com",
            "port": "587",
            "security": "starttls",
            "from_address": "comsense@example.com",
            "back": "/setup/email",
            "next": "/setup/email",
            "csrf_token": csrf,
        },
        follow_redirects=False,
    )
    assert r.headers["location"] == "/setup/email"
    db.expire_all()
    assert get_email_settings(db).configured
    assert "Send test email" in client.get("/setup/email").text

    # A return page outside the wizard and Settings is ignored.
    r = client.post(
        "/settings/email",
        data={"host": "", "from_address": "", "next": "https://evil.example", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.headers["location"] == "/settings"

    # Step 3: package and first enrollment code, for a new customer.
    page = client.get("/setup/agent").text
    pkg = re.search(r'href="/downloads/(pfSense-pkg-ComSense-[^"]+\.pkg)"', page).group(1)
    assert "https://agents.example.com:10443/downloads/" + pkg in page
    download = client.get(f"/downloads/{pkg}")
    assert download.status_code == 200
    assert hashlib.sha256(download.content).hexdigest() in page

    r = client.post("/setup/agent/key", data={"customer": "Acme Corp", "csrf_token": csrf}, follow_redirects=False)
    assert r.headers["location"] == "/setup/agent"
    page = client.get("/setup/agent").text
    code = re.search(r'value="(csfm1\.[^"]+)"', page).group(1)
    assert parse_code(code)["url"] == "https://agents.example.com:10443"
    db.expire_all()
    acme = db.scalar(select(Organization).where(Organization.name == "Acme Corp"))
    key = db.scalar(select(EnrollmentKey).where(EnrollmentKey.organization_id == acme.id))
    assert key.max_uses == 1 and key.expires_at is not None
    assert "csfm1." not in client.get("/setup/agent").text  # shown once

    client.post("/setup/finish", data={"csrf_token": csrf})
    db.expire_all()
    assert get_site_settings(db).setup_completed_at


def test_agent_package_is_a_valid_pkg_archive(tmp_path):
    port = find_port_dir()
    name, data = build_package(port)
    assert re.fullmatch(r"pfSense-pkg-ComSense-\d+\.\d+\.\d+\.pkg", name)
    assert build_package(port)[1] == data  # reproducible

    with tarfile.open(fileobj=io.BytesIO(lzma.decompress(data))) as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        # pkg reads the manifests first and stops at the first file not starting with "+".
        assert names[:2] == ["+COMPACT_MANIFEST", "+MANIFEST"]
        manifest = json.loads(tar.extractfile("+MANIFEST").read())
        compact = json.loads(tar.extractfile("+COMPACT_MANIFEST").read())
        files = {m.name: (m, tar.extractfile(m).read()) for m in members[2:]}

    assert manifest["name"] == compact["name"] == "pfSense-pkg-ComSense"
    assert manifest["abi"] == "FreeBSD:*" and manifest["prefix"] == "/"
    # Shown (and removable) in pfSense's Installed Packages page, which filters on pkg query %R.
    assert manifest["annotations"]["repository"] == "pfSense"
    assert "files" not in compact
    assert set(manifest["files"]) == set(files)
    for path, (member, content) in files.items():
        assert path.startswith("/")
        assert manifest["files"][path] == "1$" + hashlib.sha256(content).hexdigest()
        assert member.uname == "root" and member.gname == "wheel"
        assert b"%%" not in content, path
    assert files["/usr/local/sbin/comsense-agentd"][0].mode == 0o755
    assert manifest["flatsize"] == sum(len(c) for _, c in files.values())
    # /etc/rc.packages strips "pfSense-pkg-" from the package name, reads
    # /usr/local/share/<package>/info.xml and then looks the package up by that name
    # (case-sensitive) among the registered ones. A mismatch aborts the install.
    import xml.etree.ElementTree as ET

    short = manifest["name"].removeprefix("pfSense-pkg-")
    info_path = f"/usr/local/share/{manifest['name']}/info.xml"
    info = ET.fromstring(files[info_path][1]).find("package")
    assert info.findtext("name") == short
    assert info.findtext("internal_name") == "comsense"  # the service name pfSense stops on removal
    assert info.findtext("version") == manifest["version"]
    post = manifest["scripts"]["post-install"]
    assert "/etc/rc.packages pfSense-pkg-ComSense POST-INSTALL" in post and not post.startswith("#!")

    # Written once; a package an admin put there under the same name is kept.
    downloads = tmp_path / "downloads"
    target = ensure_package(downloads)
    assert target.read_bytes() == data
    mtime = target.stat().st_mtime_ns
    ensure_package(downloads)
    assert target.stat().st_mtime_ns == mtime
    (downloads / ".generated").unlink()
    target.write_bytes(b"custom build")
    ensure_package(downloads)
    assert target.read_bytes() == b"custom build"


def test_agent_package_installs_on_every_architecture():
    # pkg accepts a package when strncasecmp or fnmatch(abi, system ABI) matches (libpkg utils.c is_valid_abi);
    # fnmatch without FNM_PATHNAME lets "*" span the ":" separators, like Python's fnmatchcase.
    from fnmatch import fnmatchcase

    from app.services.agentpkg import ABI

    systems = [
        "FreeBSD:14:amd64",    # pfSense CE 2.7 / 2.8, Plus on x86
        "FreeBSD:15:amd64",
        "FreeBSD:16:amd64",
        "FreeBSD:14:aarch64",  # Netgate 1100 / 2100 / 4200 / 6100 class ARM64 boxes
        "FreeBSD:15:aarch64",
        "FreeBSD:16:aarch64",
        "FreeBSD:14:armv7",    # older 32-bit ARM appliances (SG-3100)
    ]
    for system in systems:
        assert fnmatchcase(system, ABI), system


def test_architecture_is_recorded_and_shown(client, db, agent):
    from conftest import SYSTEM

    login(client)
    device = enroll(agent, make_key(db), system={**SYSTEM, "arch": "arm64"})
    page = client.get(f"/devices/{device['device_id']}").text
    assert "Architecture" in page and "ARM64" in page
    assert "ARM64" in client.get("/devices").text
