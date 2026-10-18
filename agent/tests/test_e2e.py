"""End-to-end test: the real PHP agent against the real server over TLS.

pfSense functions are stubbed by harness.php; everything else (HTTPS with
certificate verification, enrollment, check-in, backups, policies, tasks,
restore) is the production code path.

Run with:  python -m pytest agent/tests/test_e2e.py
Needs: php (with curl) and the server requirements installed.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = ROOT / "agent/pfSense-pkg-ComSense/files/usr/local/pkg/comsense"
HARNESS = Path(__file__).with_name("harness.php")
sys.path.insert(0, str(ROOT / "server"))

pytestmark = pytest.mark.skipif(not shutil.which("php"), reason="php is required")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(port: int, proc: subprocess.Popen) -> None:
    for _ in range(150):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError(proc.stdout.read().decode())


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("e2e")
    from app.security import generate_fernet_key

    web_port, agent_port = _free_port(), _free_port()
    server_env = {
        **os.environ,
        "CSFM_DATABASE_URL": f"sqlite:///{d / 'server.db'}",
        "CSFM_SECRET_KEY": "s" * 48,
        "CSFM_BACKUP_ENCRYPTION_KEY": generate_fernet_key(),
        "CSFM_DATA_DIR": str(d / "data"),
        "CSFM_RUN_SCHEDULER": "false",
        "CSFM_INITIAL_ADMIN_PASSWORD": "e2e-admin-password",
        "CSFM_PUBLIC_URL": "https://localhost",
        "CSFM_WEB_HOST": "127.0.0.1",
        "CSFM_WEB_PORT": str(web_port),
        "CSFM_AGENT_HOST": "127.0.0.1",
        "CSFM_AGENT_PORT": str(agent_port),
    }
    # The production entry point: web console + agent listener with a self-issued, pinned certificate.
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.serve"],
        cwd=ROOT / "server", env=server_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    _wait_for(web_port, proc)
    _wait_for(agent_port, proc)

    from cryptography import x509

    from app.db import init_engine, session_factory
    from app.tls import spki_pin

    pin = spki_pin(x509.load_pem_x509_certificate((d / "data" / "tls" / "agent.pem").read_bytes()))
    init_engine(server_env["CSFM_DATABASE_URL"])
    fw = d / "firewall"
    (fw / "db").mkdir(parents=True)
    yield {"dir": d, "fw": fw, "web_port": web_port, "agent_port": agent_port, "pin": pin, "db": session_factory()}
    proc.terminate()
    proc.wait(timeout=10)


def agent(env, *args: str) -> str:
    result = subprocess.run(
        ["php", str(HARNESS), *args],
        env={**os.environ, "CSFM_TEST_DIR": str(env["fw"]), "CSFM_AGENT_DIR": str(AGENT_DIR)},
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def fw_config(env) -> dict:
    return json.loads((env["fw"] / "config.json").read_text())


def set_fw_settings(env, **changes) -> None:
    cfg = fw_config(env) if (env["fw"] / "config.json").exists() else {
        "system": {"hostname": "fw-e2e", "domain": "example.net"}
    }
    pkg = cfg.setdefault("installedpackages", {}).setdefault("comsense", {}).setdefault("config", [{}])
    pkg[0].update(changes)
    (env["fw"] / "config.json").write_text(json.dumps(cfg))


def test_full_lifecycle(env):
    from sqlalchemy import select

    from app.models import (
        Backup, Device, EnrollmentKey, Policy, PolicyAssignment, PolicyType, Task, TaskStatus, TaskType,
    )
    from app.security import generate_enrollment_key, hash_secret, key_display_prefix
    from app.services.tasks import queue_task

    key = generate_enrollment_key()
    with env["db"]() as db:
        db.add(EnrollmentKey(name="e2e", prefix=key_display_prefix(key), key_hash=hash_secret(key)))
        db.commit()

    from app.enrollment import make_code

    url = f"https://localhost:{env['agent_port']}"
    caps = dict(allow_backup="on", allow_policy="on", allow_services="on", allow_restore="on")

    # The web console port does not answer the agent API at all.
    import httpx

    web = httpx.get(f"http://127.0.0.1:{env['web_port']}/api/agent/v1/ping", trust_env=False)
    assert web.status_code == 404

    def last_error() -> str:
        return json.loads(agent(env, "state"))["state"]["last_error"]["message"]

    # 1. A wrong key is refused by the server and nothing is stored.
    set_fw_settings(env, enable="on", enrollment_key=make_code(url, "csfm_enr_wrong", env["pin"]), **caps)
    assert agent(env, "run") == "Enrollment failed"
    assert "403" in last_error()

    # 2. A pin for some other key: the TLS connection is refused before anything is sent.
    other_pin = base64.b64encode(b"x" * 32).decode()
    set_fw_settings(env, enrollment_key=make_code(url, key, other_pin))
    assert agent(env, "run") == "Enrollment failed"
    assert "reach" in last_error()

    # 3. No pin and no CA: the self-issued certificate is not trusted (no silent downgrade).
    set_fw_settings(env, enrollment_key=key, server_url=url, pin_sha256="")
    assert agent(env, "run") == "Enrollment failed"
    assert "reach" in last_error()

    # A damaged code is reported as such.
    set_fw_settings(env, enrollment_key="csfm1.not-base64!")
    assert agent(env, "run") == "Enrollment failed"
    assert "damaged" in last_error()

    set_fw_settings(env, enrollment_key=make_code(url, key, env["pin"]))

    # 3. The right code enrolls over the pinned connection. The key is wiped from
    #    config; the URL and pin that came with it are kept. A backup is uploaded.
    assert agent(env, "run") == "Checked in; ran 0 task(s)"
    pkg_settings = fw_config(env)["installedpackages"]["comsense"]["config"][0]
    assert pkg_settings["enrollment_key"] == ""
    assert pkg_settings["server_url"] == url and pkg_settings["pin_sha256"] == env["pin"]
    creds = json.loads(agent(env, "state"))["credentials"]
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        assert device.hostname == "fw-e2e.example.net" and device.wan_ip == "198.51.100.20"
        assert device.capabilities == ["backup", "policy", "restore", "services"]
        assert device.updates["update_available"] is True
        assert db.scalar(select(Backup).where(Backup.device_id == device.id)) is not None

    # 4. Policies and tasks.
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        rules = Policy(name="rules", type=PolicyType.firewall_rules, content={"rules": [{
            "interface": "wan", "type": "pass", "protocol": "tcp",
            "source": {"address": "CSFM_E2E"}, "destination": {"network": "wanip", "port": "443"},
            "descr": "NOC to GUI"}]})
        aliases = Policy(name="aliases", type=PolicyType.aliases, content={"aliases": [
            {"name": "CSFM_E2E", "type": "host", "address": ["203.0.113.5"]}]})
        system = Policy(name="system", type=PolicyType.system, content={"timezone": "Etc/UTC", "dnsservers": ["9.9.9.9"]})
        # Rules policy is created first on purpose: the agent must still apply aliases first.
        db.add_all([rules, aliases, system])
        db.flush()
        for p in (rules, aliases, system):
            db.add(PolicyAssignment(policy_id=p.id, device_id=device.id))
        queue_task(db, device, TaskType.restart_service, {"service": "unbound"}, actor="e2e")
        queue_task(db, device, TaskType.check_updates, actor="e2e")
        db.commit()
        policy_ids = {p.name: p.id for p in (rules, aliases, system)}

    assert agent(env, "run").startswith("Checked in; ran 5 task(s)")
    cfg = fw_config(env)
    assert [a["name"] for a in cfg["aliases"]["alias"]] == ["CSFM_E2E"]
    assert cfg["filter"]["rule"][0]["descr"] == "[CSFM] NOC to GUI"
    assert cfg["system"]["timezone"] == "Etc/UTC" and cfg["system"]["dnsserver"] == ["9.9.9.9"]
    actions = (env["fw"] / "actions.log").read_text()
    assert actions.index("applied alias policy") < actions.index("applied firewall rule policy")
    assert "restart unbound" in actions

    with env["db"]() as db:
        tasks = db.scalars(select(Task).where(Task.device_id == creds["device_id"])).all()
        assert all(t.status == TaskStatus.success for t in tasks), [(t.type, t.output) for t in tasks]

    # Next check-in reports hashes, so nothing is re-applied.
    assert agent(env, "run") == "Checked in; ran 0 task(s)"

    # 5. Unassigning removes rules before the alias they reference, and restores system values.
    with env["db"]() as db:
        db.query(PolicyAssignment).delete()
        db.commit()
    assert agent(env, "run") == "Checked in; ran 3 task(s)"
    cfg = fw_config(env)
    assert cfg["filter"]["rule"] == [] and cfg["aliases"]["alias"] == []
    assert "timezone" not in cfg["system"] and "dnsserver" not in cfg["system"]
    assert json.loads(agent(env, "state"))["state"]["policies"] == []

    # 6. The firewall's local settings override the server: reboot is not allowed.
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        device.capabilities = device.capabilities + ["reboot"]  # pretend the server thinks it's allowed
        reboot = queue_task(db, device, TaskType.reboot, actor="e2e")
        db.commit()
        reboot_id = reboot.id
    agent(env, "run")
    with env["db"]() as db:
        reboot = db.get(Task, reboot_id)
        assert reboot.status == TaskStatus.failed and "not allowed" in reboot.output

    # 7. Restore a stored backup.
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        backup = db.scalar(select(Backup).where(Backup.device_id == device.id).order_by(Backup.id))
        restore = queue_task(db, device, TaskType.restore_backup, {"backup_id": backup.id}, actor="e2e")
        db.commit()
        restore_id = restore.id
    agent(env, "run")
    with env["db"]() as db:
        restore = db.get(Task, restore_id)
        assert restore.status == TaskStatus.success, restore.output
    assert "mwexec_bg: /etc/rc.reboot" in (env["fw"] / "actions.log").read_text()
    restored = (env["fw"] / "conf" / "config.xml").read_text()
    assert "<pfsense>" in restored

    # 8. A disabled device is locked out.
    with env["db"]() as db:
        from app.models import DeviceStatus

        db.get(Device, creds["device_id"]).status = DeviceStatus.disabled
        db.commit()
    assert agent(env, "run") == "Check-in failed"
    with env["db"]() as db:
        assert db.get(Device, creds["device_id"]).last_seen_at is not None
