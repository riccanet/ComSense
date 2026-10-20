"""Agents up to 0.2.9 cannot replace themselves (plain `pkg add`); they get a bootstrap package."""
from __future__ import annotations

import hashlib
import io
import json
import lzma
import os
import subprocess
import tarfile

from conftest import auth, enroll, login, make_key

from app.models import Task, TaskType
from app.services import agentpkg


def _open(data: bytes) -> tarfile.TarFile:
    return tarfile.open(fileobj=io.BytesIO(lzma.decompress(data)))


def test_bootstrap_package_carries_the_real_one_and_installs_it_forced():
    real = lzma.compress(b"real package bytes")
    boot = agentpkg.build_bootstrap(real, "0.2.10")
    assert boot == agentpkg.build_bootstrap(real, "0.2.10")  # reproducible
    tar = _open(boot)
    compact = json.loads(tar.extractfile("+COMPACT_MANIFEST").read())
    full = json.loads(tar.extractfile("+MANIFEST").read())
    assert compact["name"] == agentpkg.BOOTSTRAP_NAME != agentpkg.NAME and compact["version"] == "0.2.10"
    path = f"{agentpkg.BOOTSTRAP_DIR}/agent-update.pkg"
    assert tar.extractfile(path).read() == real
    assert full["files"] == {path: "1$" + hashlib.sha256(real).hexdigest()}
    script = full["scripts"]["post-install"]
    assert script.startswith("/usr/sbin/daemon -f /bin/sh -c '") and script.count("'") == 2
    assert f"pkg-static add -f {path}" in script and f"pkg-static delete -y {agentpkg.BOOTSTRAP_NAME}" in script
    # pfSense must not list it as a package of its own.
    assert "annotations" not in compact


def test_bootstrap_job_runs_in_order(tmp_path):
    """The background job's shell, with pkg, pgrep and the rc script replaced by recorders."""
    log = tmp_path / "calls"
    for name in ("pkg-static", "pgrep", "comsense.sh"):
        tool = tmp_path / name
        tool.write_text(f'#!/bin/sh\necho "{name} $*" >> {log}\n' + ("exit 1\n" if name == "pgrep" else ""))
        tool.chmod(0o755)
    job = (agentpkg._BOOTSTRAP_JOB.replace("sleep 3; ", "")
           .replace("/usr/local/sbin/pkg-static", str(tmp_path / "pkg-static"))
           .replace("/bin/pgrep", str(tmp_path / "pgrep"))
           .replace("/usr/local/etc/rc.d/comsense.sh", str(tmp_path / "comsense.sh"))
           .replace("/var/db/comsense", str(tmp_path)))
    subprocess.run(["/bin/sh", "-c", job], check=True, timeout=30, env={**os.environ, "PATH": "/usr/bin:/bin"})
    calls = log.read_text().splitlines()
    assert calls == [
        "pgrep -q -x pkg-static", "pgrep -q -x pkg",
        f"pkg-static add -f {agentpkg.BOOTSTRAP_DIR}/agent-update.pkg",
        f"pkg-static delete -y {agentpkg.BOOTSTRAP_NAME}",
        "comsense.sh restart",
    ]
    assert (tmp_path / "checkin-now").exists()
    assert "Bootstrap: installing" in (tmp_path / "agent-update.log").read_text()


def test_old_agents_get_the_bootstrap_and_new_ones_the_package(client, db, agent, settings):
    package = agentpkg.latest_package(settings.data_dir / "downloads")
    csrf = login(client)
    for reported, bootstrap in (("0.2.7", True), ("0.2.10", False)):
        creds = enroll(agent, make_key(db), system={"hostname": f"fw-{reported}", "unique_id": reported})
        agent.post("/api/agent/v1/checkin", json={"agent_version": reported}, headers=auth(creds["token"]))
        if not agentpkg.agent_outdated(reported, package["version"]):
            continue
        client.post(f"/devices/{creds['device_id']}/update-agent", data={"csrf_token": csrf})
        task = db.query(Task).filter(Task.device_id == creds["device_id"], Task.type == TaskType.update_agent).one()
        assert task.payload["file"] == package["name"]  # the name the old agent insists on
        data = agent.get(f"/api/agent/v1/agent-package/{package['name']}", headers=auth(creds["token"])).content
        assert hashlib.sha256(data).hexdigest() == task.payload["sha256"]
        name = json.loads(_open(data).extractfile("+COMPACT_MANIFEST").read())["name"]
        assert name == (agentpkg.BOOTSTRAP_NAME if bootstrap else agentpkg.NAME)
