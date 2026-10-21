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
        # The end-to-end test exercises policies, restarts and restores ("coming soon" by default).
        "CSFM_ENABLE_FIREWALL_CHANGES": "true",
        "CSFM_PUBLIC_URL": "https://localhost",
        # The test talks plain HTTP to the web port (no TLS proxy in front).
        "CSFM_SECURE_COOKIES": "false",
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


def agent(env, *args: str, extra_env: dict | None = None) -> str:
    result = subprocess.run(
        ["php", str(HARNESS), *args],
        env={**os.environ, "CSFM_TEST_DIR": str(env["fw"]), "CSFM_AGENT_DIR": str(AGENT_DIR), **(extra_env or {})},
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
        Backup, Device, DeviceGroup, EnrollmentKey, Policy, PolicyAssignment, PolicyType, Task, TaskStatus, TaskType,
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
    # The update check never runs inside a cycle: it is started in the background afterwards
    # (a slow package repository must not hold up check-ins) and reported next time.
    assert "agent.php check-updates" in (env["fw"] / "actions.log").read_text()
    with env["db"]() as db:
        assert not db.get(Device, json.loads(agent(env, "state"))["credentials"]["device_id"]).updates
    agent(env, "check-updates")
    assert agent(env, "run") == "Checked in; ran 0 task(s)"
    pkg_settings = fw_config(env)["installedpackages"]["comsense"]["config"][0]
    assert pkg_settings["enrollment_key"] == ""
    assert pkg_settings["server_url"] == url and pkg_settings["pin_sha256"] == env["pin"]
    creds = json.loads(agent(env, "state"))["credentials"]
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        assert device.hostname == "fw-e2e.example.net" and device.wan_ip == "198.51.100.20"
        assert device.capabilities == ["backup", "policy", "restore", "services"]
        # A package service whose status check fails (its function lives in a file the CLI has not
        # loaded, as with comsense_running() on a real firewall) is reported as unknown; the check-in
        # still happens.
        # The busiest processes come with every check-in (real ps output here).
        procs = device.inventory["processes"]
        assert procs["total"] > 0 and procs["top"] and {"pid", "cpu", "rss_kb", "command"} <= set(procs["top"][0])
        assert all(len(p["command"]) <= 160 for p in procs["top"])
        services = {s["name"]: s["running"] for s in device.inventory["services"]}
        assert services == {"unbound": True, "comsense": None}
        assert device.updates["update_available"] is True and device.updates["version"] == "2.7.2"
        # pfSense-upgrade calls pfSense-repoc and pkg by name: the agent gives it root's PATH.
        assert "/usr/local/sbin" in (env["fw"] / "upgrade-path").read_text().split(":")
        # ...and root's SSL_CERT_DIR, without which pfSense-repoc never learns of a new version.
        assert (env["fw"] / "upgrade-certdir").read_text().strip() == ("/etc/ssl/certs/" if Path("/etc/ssl/certs").is_dir() else "")
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
        forwards = Policy(name="forwards", type=PolicyType.port_forward, content={"rules": [{
            "interface": "wan", "protocol": "tcp", "destination": {"network": "wanip", "port": "8443"},
            "target": "CSFM_E2E", "local_port": "443", "descr": "Web server"}]})
        # Rules and port forwards are created first on purpose: the agent must still apply aliases first.
        db.add_all([rules, forwards, aliases, system])
        db.flush()
        # Port forwards go to a firewall group the firewall belongs to.
        group = DeviceGroup(name="e2e-sites", devices=[device])
        db.add(group)
        db.flush()
        for p in (rules, aliases, system):
            db.add(PolicyAssignment(policy_id=p.id, device_id=device.id))
        db.add(PolicyAssignment(policy_id=forwards.id, group_id=group.id))
        queue_task(db, device, TaskType.restart_service, {"service": "unbound"}, actor="e2e", changes_enabled=True)
        queue_task(db, device, TaskType.check_updates, actor="e2e")
        db.commit()
        policy_ids = {p.name: p.id for p in (rules, aliases, system)}

    assert agent(env, "run").startswith("Checked in; ran 6 task(s)")
    cfg = fw_config(env)
    assert [a["name"] for a in cfg["aliases"]["alias"]] == ["CSFM_E2E"]
    assert cfg["filter"]["rule"][0]["descr"] == "[CSFM] NOC to GUI"
    (fwd,) = cfg["nat"]["rule"]
    assert fwd["descr"] == "[CSFM] Web server" and fwd["target"] == "CSFM_E2E" and fwd["local-port"] == "443"
    assert fwd["destination"] == {"network": "wanip", "port": "8443"} and fwd["associated-rule-id"] == "pass"
    assert cfg["system"]["timezone"] == "Etc/UTC" and cfg["system"]["dnsserver"] == ["9.9.9.9"]
    actions = (env["fw"] / "actions.log").read_text()
    assert actions.index("applied alias policy") < actions.index("applied firewall rule policy")
    assert actions.index("applied alias policy") < actions.index("applied port forward policy")
    assert "restart unbound" in actions

    with env["db"]() as db:
        tasks = db.scalars(select(Task).where(Task.device_id == creds["device_id"])).all()
        assert all(t.status == TaskStatus.success for t in tasks), [(t.type, t.output) for t in tasks]

    # Next check-in reports hashes, so nothing is re-applied.
    assert agent(env, "run") == "Checked in; ran 0 task(s)"

    # 5. Unassigning removes rules and port forwards before the alias they reference, and restores
    #    system values. Leaving the group is enough for the group's port forwards.
    with env["db"]() as db:
        db.scalars(select(DeviceGroup)).one().devices = []
        db.query(PolicyAssignment).filter(PolicyAssignment.group_id.is_(None)).delete()
        db.commit()
    assert agent(env, "run") == "Checked in; ran 4 task(s)"
    cfg = fw_config(env)
    assert cfg["filter"]["rule"] == [] and cfg["aliases"]["alias"] == [] and cfg["nat"]["rule"] == []
    actions = (env["fw"] / "actions.log").read_text()
    assert actions.rindex("removed port forward policy") < actions.rindex("removed alias policy")
    assert "timezone" not in cfg["system"] and "dnsserver" not in cfg["system"]
    assert json.loads(agent(env, "state"))["state"]["policies"] == []

    # 5b. A change that cuts the firewall off is rolled back at once: this one points the
    #     firewall's outbound proxy at a dead port, so the agent can no longer reach the server.
    from app.models import Alert

    guard_dir = env["fw"] / "guard"
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        breaker = Policy(name="breaker", type=PolicyType.config_set, content={"items": [
            {"path": "system/proxyurl", "value": "127.0.0.1"},
            {"path": "system/proxyport", "value": str(_free_port())}]})
        db.add(breaker)
        db.flush()
        db.add(PolicyAssignment(policy_id=breaker.id, device_id=device.id))
        db.commit()
        breaker_id = breaker.id
    agent(env, "run")
    cfg = fw_config(env)
    assert "proxyurl" not in cfg["system"], "the breaking change must be undone"
    assert "mwexec: /etc/rc.reload_all" in (env["fw"] / "actions.log").read_text()
    assert not (guard_dir / "guard.json").exists()
    with env["db"]() as db:
        task = db.scalar(select(Task).where(Task.type == TaskType.apply_policy).order_by(Task.id.desc()))
        assert task.status == TaskStatus.failed and "Rolled back" in task.output
    # The next check-in reports the rollback: an alert, and the change is not sent again.
    assert agent(env, "run") == "Checked in; ran 0 task(s)"
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        assert str(breaker_id) in device.rolled_back_policies
        assert db.scalar(select(Alert).where(Alert.device_id == device.id, Alert.key.like("rollback:%"),
                                             Alert.resolved_at.is_(None))) is not None
    assert agent(env, "run") == "Checked in; ran 0 task(s)"
    assert json.loads(agent(env, "state"))["state"].get("rollbacks") == []
    with env["db"]() as db:
        db.query(PolicyAssignment).delete()
        db.get(Device, creds["device_id"]).rolled_back_policies = {}
        db.commit()

    # 5c. A change that passes the first check but loses contact later is rolled back by the
    #     watchdog when its probation window ends.
    with env["db"]() as db:
        late = Policy(name="late", type=PolicyType.aliases, content={"aliases": [
            {"name": "CSFM_LATE", "type": "host", "address": ["203.0.113.9"]}]})
        db.add(late)
        db.flush()
        db.add(PolicyAssignment(policy_id=late.id, device_id=creds["device_id"]))
        db.commit()
        late_id = late.id
    short = {"CSFM_TEST_GUARD_WINDOW": "1"}
    assert agent(env, "run", extra_env=short) == "Checked in; ran 1 task(s)"
    assert [a["name"] for a in fw_config(env)["aliases"]["alias"]] == ["CSFM_LATE"]
    assert (guard_dir / "guard.json").exists()
    # Contact is lost some time after the change (simulated: the proxy goes bad).
    cfg = fw_config(env)
    cfg["system"].update(proxyurl="127.0.0.1", proxyport=str(_free_port()))
    (env["fw"] / "config.json").write_text(json.dumps(cfg))
    time.sleep(1.2)
    assert agent(env, "watchdog") == "Change rolled back"
    cfg = fw_config(env)
    assert not cfg.get("aliases", {}).get("alias") and "proxyurl" not in cfg["system"]
    assert str(late_id) not in json.loads(agent(env, "state"))["state"]["policies"]
    assert agent(env, "run") == "Checked in; ran 0 task(s)"
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        assert device.rolled_back_policies.get(str(late_id))
        late_task = db.scalar(select(Task).where(Task.type == TaskType.apply_policy).order_by(Task.id.desc()))
        assert late_task.status == TaskStatus.failed and "Rolled back on the firewall" in late_task.output

    # 5d. Cleared on the server, it is sent again; a check-in after the change confirms it.
    with env["db"]() as db:
        db.get(Device, creds["device_id"]).rolled_back_policies = {}
        db.commit()
    assert agent(env, "run") == "Checked in; ran 1 task(s)"
    assert (guard_dir / "guard.json").exists()
    assert agent(env, "run") == "Checked in; ran 0 task(s)"
    assert not (guard_dir / "guard.json").exists()
    assert [a["name"] for a in fw_config(env)["aliases"]["alias"]] == ["CSFM_LATE"]
    with env["db"]() as db:
        db.query(PolicyAssignment).delete()
        db.commit()
    assert agent(env, "run") == "Checked in; ran 1 task(s)"
    assert agent(env, "run") == "Checked in; ran 0 task(s)"
    assert fw_config(env)["aliases"]["alias"] == [] and not (guard_dir / "guard.json").exists()

    # 6. The firewall's local settings override the server: reboot is not allowed.
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        device.capabilities = device.capabilities + ["reboot"]  # pretend the server thinks it's allowed
        reboot = queue_task(db, device, TaskType.reboot, actor="e2e", changes_enabled=True)
        db.commit()
        reboot_id = reboot.id
    agent(env, "run")
    with env["db"]() as db:
        reboot = db.get(Task, reboot_id)
        assert reboot.status == TaskStatus.failed and "not allowed" in reboot.output

    # 7. Restore a stored backup. It keeps the firewall's current ComSense settings, not the backup's.
    cfg = fw_config(env)
    cfg["installedpackages"]["comsense"]["config"][0]["restore_marker"] = "current-permissions"
    (env["fw"] / "config.json").write_text(json.dumps(cfg))
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        backup = db.scalar(select(Backup).where(Backup.device_id == device.id).order_by(Backup.id.desc()))
        restore = queue_task(db, device, TaskType.restore_backup, {"backup_id": backup.id}, actor="e2e", changes_enabled=True)
        db.commit()
        restore_id = restore.id
    agent(env, "run")
    with env["db"]() as db:
        restore = db.get(Task, restore_id)
        assert restore.status == TaskStatus.success, restore.output
    assert "mwexec_bg: /etc/rc.reboot" in (env["fw"] / "actions.log").read_text()
    # After the reboot the restore is on probation; the watchdog reboots back if contact is lost.
    guard = json.loads((guard_dir / "guard.json").read_text())
    assert guard["mode"] == "reboot" and guard["tasks"][0]["id"] == restore_id
    restored = (env["fw"] / "conf" / "config.xml").read_text()
    assert "<pfsense>" in restored and "<restore_marker>current-permissions</restore_marker>" in restored

    # 8. Between check-ins the agent waits on the server, which answers early when work is queued.
    def wait(seconds: str):
        return subprocess.run(
            ["php", str(HARNESS), "wait", seconds],
            env={**os.environ, "CSFM_TEST_DIR": str(env["fw"]), "CSFM_AGENT_DIR": str(AGENT_DIR)},
            capture_output=True, text=True, timeout=120,
        )

    idle = wait("1")
    assert (idle.returncode, idle.stdout.strip()) == (1, "idle"), idle.stdout + idle.stderr
    with env["db"]() as db:
        queue_task(db, db.get(Device, creds["device_id"]), TaskType.refresh_inventory, actor="e2e")
        db.commit()
    woke = wait("50")
    assert (woke.returncode, woke.stdout.strip()) == (0, "wake"), woke.stdout + woke.stderr
    agent(env, "run")

    # 9. Self-update: an older agent downloads the server's package over its API, checks the hash and
    # hands it to pkg in a detached process; the next cycle (now the new version) reports success.
    from app.services.agentpkg import latest_package

    package = latest_package(env["dir"] / "data" / "downloads")
    # An agent that replaces itself (0.2.10 and later; older ones get the bootstrap, server tests):
    # a pre-release of the served version is older to the agent and needs no bootstrap.
    old_version = package["version"] + "-rc1"
    old = {"CSFM_TEST_AGENT_VERSION": old_version}
    set_fw_settings(env, allow_upgrade="on")  # self-updates need the firewall's "upgrade" permission
    agent(env, "run", extra_env=old)
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        assert "upgrade" in device.capabilities and device.agent_version == old_version
        bad = queue_task(db, device, TaskType.update_agent,
                         {"version": package["version"], "file": package["name"], "sha256": "0" * 64}, actor="e2e")
        db.commit()
        bad_id = bad.id
    agent(env, "run", extra_env=old)
    with env["db"]() as db:
        bad = db.get(Task, bad_id)
        assert bad.status == TaskStatus.failed and "Checksum mismatch" in bad.output
    with env["db"]() as db:
        device = db.get(Device, creds["device_id"])
        task = queue_task(db, device, TaskType.update_agent,
                          {"version": package["version"], "file": package["name"], "sha256": package["sha256"]},
                          actor="e2e")
        db.commit()
        task_id = task.id
    agent(env, "run", extra_env=old)
    with env["db"]() as db:
        assert db.get(Task, task_id).status == TaskStatus.running
    staged = env["fw"] / "db" / "agent-update.pkg"
    assert staged.read_bytes() == (env["dir"] / "data" / "downloads" / package["name"]).read_bytes()
    actions = (env["fw"] / "actions.log").read_text()
    assert "/usr/sbin/daemon -f /bin/sh -c " in actions and "pkg-static add -f " in actions
    assert "checkin-now" in actions  # the restarted agent checks in at once
    agent(env, "run")  # pkg installed the new files: this is the new agent
    with env["db"]() as db:
        task = db.get(Task, task_id)
        assert task.status == TaskStatus.success, task.output
        assert f"-> {package['version']}" in task.output
        assert db.get(Device, creds["device_id"]).agent_version == package["version"]
    assert not staged.exists()

    # 10. Remote terminal: an admin approves the session with their authenticator code, the firewall's
    # helper connects out over a WebSocket (pinned TLS) and runs a real shell on a pseudo-terminal.
    terminal_session(env, creds)

    # 10b. Single changes from the firewall's page: add a port forward, remove it again by the fingerprint the
    #      server reads from config.xml, and switch pfSense's email notifications.
    from app.services.configview import port_forwards_from_xml, smtp_notifications_from_xml

    def queue(ttype, payload):
        with env["db"]() as db:
            t = queue_task(db, db.get(Device, creds["device_id"]), ttype, payload, actor="e2e", changes_enabled=True)
            db.commit()
            return t.id

    def task(tid):
        with env["db"]() as db:
            return db.get(Task, tid)

    def pfsense_xml() -> bytes:
        """The firewall's config as pfSense writes config.xml (the harness keeps it as JSON)."""
        from xml.sax.saxutils import escape

        def render(tag, value):
            if isinstance(value, list):
                return "".join(render(tag, v) for v in value)
            if isinstance(value, dict):
                return f"<{tag}>" + "".join(render(k, v) for k, v in value.items()) + f"</{tag}>"
            if value is True or value == "":
                return f"<{tag}></{tag}>"
            return f"<{tag}>{escape(str(value))}</{tag}>"

        cfg = fw_config(env)
        return ('<?xml version="1.0"?>\n' + render("pfsense", {"version": "23.3", **cfg})).encode()

    tid = queue(TaskType.nat_add, {"rule": {
        "interface": "wan", "protocol": "tcp", "source": {"any": True},
        "destination": {"network": "wanip", "port": "8080"}, "target": "192.168.1.50", "local_port": "80",
        "descr": "Manual web"}})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    (fwd,) = [r for r in port_forwards_from_xml(pfsense_xml()) if r["descr"] == "Manual web"]
    assert not fwd["managed"] and fwd["target"] == "192.168.1.50"
    tid = queue(TaskType.nat_edit, {"fingerprint": fwd["fingerprint"], "rule": {
        "interface": "wan", "protocol": "tcp/udp", "source": {"address": "203.0.113.0/24"},
        "destination": {"network": "wanip", "port": "8081"}, "target": "192.168.1.51", "local_port": "8080",
        "descr": "Manual web", "disabled": True}})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    (edited,) = [r for r in port_forwards_from_xml(pfsense_xml()) if r["descr"] == "Manual web"]
    assert (edited["target"], edited["local_port"], edited["port"], edited["protocol"], edited["src"],
            edited["disabled"]) == ("192.168.1.51", "8080", "8081", "tcp/udp", "203.0.113.0/24", True)
    raw = [r for r in fw_config(env)["nat"]["rule"] if r.get("descr") == "Manual web"][0]
    assert raw["associated-rule-id"] == "pass" and "created" in raw  # kept from the original
    tid = queue(TaskType.nat_edit, {"fingerprint": fwd["fingerprint"], "rule": {  # the old fingerprint
        "destination": {"network": "wanip", "port": "1"}, "target": "192.168.1.1", "local_port": "1"}})
    agent(env, "run")
    assert task(tid).status == TaskStatus.failed and "no longer on the firewall" in task(tid).output
    fwd = edited
    tid = queue(TaskType.nat_remove, {"fingerprint": fwd["fingerprint"], "descr": "Manual web"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    assert not [r for r in fw_config(env).get("nat", {}).get("rule", []) if r.get("descr") == "Manual web"]
    tid = queue(TaskType.nat_remove, {"fingerprint": fwd["fingerprint"], "descr": "Manual web"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.failed and "no longer on the firewall" in task(tid).output

    # A port forward made in pfSense with a linked filter rule: the rule follows an edit.
    cfg = fw_config(env)
    cfg.setdefault("nat", {}).setdefault("rule", []).append({
        "source": {"any": ""}, "destination": {"network": "wanip", "port": "2222"}, "protocol": "tcp",
        "target": "192.168.1.60", "local-port": "22", "interface": "wan", "descr": "SSH",
        "associated-rule-id": "nat_abc123"})
    cfg.setdefault("filter", {}).setdefault("rule", []).append({
        "type": "pass", "interface": "wan", "protocol": "tcp", "source": {"any": ""},
        "destination": {"address": "192.168.1.60", "port": "22"}, "descr": "NAT SSH",
        "associated-rule-id": "nat_abc123"})
    (env["fw"] / "config.json").write_text(json.dumps(cfg))
    (ssh,) = [r for r in port_forwards_from_xml(pfsense_xml()) if r["descr"] == "SSH"]
    assert ssh["filter_rule"] == "linked"
    tid = queue(TaskType.nat_edit, {"fingerprint": ssh["fingerprint"], "rule": {
        "interface": "wan", "protocol": "tcp", "source": {"any": True},
        "destination": {"network": "wanip", "port": "2222"}, "target": "192.168.1.61", "local_port": "2200",
        "descr": "SSH jump"}})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success and "linked firewall rule" in task(tid).output
    (linked,) = [f for f in fw_config(env)["filter"]["rule"] if f.get("associated-rule-id") == "nat_abc123"]
    assert linked["destination"] == {"address": "192.168.1.61", "port": "2200"} and linked["descr"] == "NAT SSH jump"

    # Aliases one at a time from the Configuration page.
    from app.services.configview import aliases_from_xml

    def alias(name):
        return next((a for a in aliases_from_xml(pfsense_xml()) if a["name"] == name), None)

    tid = queue(TaskType.alias_add, {"alias": {"name": "Cameras", "type": "host", "address": ["192.168.1.40"],
                                               "descr": "CCTV", "detail": ["Door"]}})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    assert alias("Cameras")["entry_list"] == [{"value": "192.168.1.40", "note": "Door"}]
    tid = queue(TaskType.alias_add, {"alias": {"name": "Cameras", "type": "host", "address": ["192.168.1.9"]}})
    agent(env, "run")
    assert task(tid).status == TaskStatus.failed and "already exists" in task(tid).output
    tid = queue(TaskType.alias_edit, {"alias": {"name": "Cameras", "type": "network",
                                                "address": ["192.168.1.40", "192.168.2.0/24"], "descr": "CCTV v2"}})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    cams = alias("Cameras")
    assert (cams["type"], cams["descr"], [e["value"] for e in cams["entry_list"]]) == \
        ("network", "CCTV v2", ["192.168.1.40", "192.168.2.0/24"])
    cfg = fw_config(env)
    cfg["filter"]["rule"].append({"type": "block", "interface": "lan", "source": {"address": "Cameras"},
                                  "destination": {"any": ""}, "descr": "No cameras out"})
    (env["fw"] / "config.json").write_text(json.dumps(cfg))
    tid = queue(TaskType.alias_remove, {"name": "Cameras"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.failed and "still used" in task(tid).output
    cfg = fw_config(env)
    cfg["filter"]["rule"] = [r for r in cfg["filter"]["rule"] if r.get("descr") != "No cameras out"]
    (env["fw"] / "config.json").write_text(json.dumps(cfg))
    tid = queue(TaskType.alias_remove, {"name": "Cameras"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success and alias("Cameras") is None
    with env["db"]() as db:  # an alias deployed from Configurations is refused here
        shared = Policy(name="shared", type=PolicyType.aliases, content={"aliases": [
            {"name": "CSFM_SHARED", "type": "host", "address": ["203.0.113.7"]}]})
        db.add(shared)
        db.flush()
        db.add(PolicyAssignment(policy_id=shared.id, device_id=creds["device_id"]))
        db.commit()
    agent(env, "run")
    assert alias("CSFM_SHARED") is not None
    tid = queue(TaskType.alias_remove, {"name": "CSFM_SHARED"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.failed and "belongs to a ComSense configuration" in task(tid).output
    with env["db"]() as db:
        db.query(PolicyAssignment).filter(PolicyAssignment.policy_id == shared.id).delete()
        db.commit()
    agent(env, "run")
    assert alias("CSFM_SHARED") is None

    # Dynamic DNS one entry at a time, and the status pfSense caches per client.
    from app.services.configview import ddns_from_xml

    entry = {"enable": True, "type": "cloudflare", "interface": "wan", "host": "vpn", "domainname": "example.com",
             "username": "", "password": "tok-1", "zoneid": "", "ttl": "", "mx": "", "updateurl": "",
             "resultmatch": "", "descr": "VPN", "wildcard": False, "proxied": True, "verboselog": False}
    tid = queue(TaskType.ddns_add, {"entry": entry})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    (vpn,) = [d for d in ddns_from_xml(pfsense_xml()) if d["host"] == "vpn"]
    assert vpn["enabled"] and vpn["proxied"] and vpn["has_password"] and vpn["fqdn"] == "vpn.example.com"
    raw = fw_config(env)["dyndnses"]["dyndns"][0]
    assert raw["password"] == "tok-1" and raw["id"] == "0"
    # pfSense caches "ip|time" per client; the agent reports it.
    (env["fw"] / "conf" / "dyndns_wancloudflare'vpn.example.com'0.cache").write_text("203.0.113.7|1760000000")
    agent(env, "run")
    with env["db"]() as db:
        inv = db.get(Device, creds["device_id"]).inventory
    assert inv["ddns"]["clients"] == [{"fingerprint": vpn["fingerprint"], "cached_ip": "203.0.113.7",
                                       "updated": "2025-10-09T08:53:20+00:00"}]
    assert {"value": "namecheap", "name": "Namecheap"} in inv["ddns"]["providers"]
    # An edit without a password keeps it; the cache goes so the next update sends the address again.
    changed = {k: v for k, v in entry.items() if k != "password"} | {"enable": False, "ttl": "300"}
    tid = queue(TaskType.ddns_edit, {"fingerprint": vpn["fingerprint"], "entry": changed})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    raw = fw_config(env)["dyndnses"]["dyndns"][0]
    assert raw["password"] == "tok-1" and raw["ttl"] == "300" and "enable" not in raw and raw["proxied"] == "yes"
    assert not list((env["fw"] / "conf").glob("dyndns_*.cache"))
    tid = queue(TaskType.ddns_remove, {"fingerprint": vpn["fingerprint"], "descr": "vpn"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success and not fw_config(env)["dyndnses"]["dyndns"]
    tid = queue(TaskType.ddns_remove, {"fingerprint": vpn["fingerprint"], "descr": "vpn"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.failed and "no longer on the firewall" in task(tid).output

    # System > Update branch: the firewall reports its branches; switching runs pfSense's pkg_switch_repo.
    assert inv["update_branch"]["current"] == "Stable"
    assert [b["name"] for b in inv["update_branch"]["branches"]] == ["Stable", "Devel"]
    tid = queue(TaskType.update_branch, {"branch": "Devel"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success, task(tid).output
    assert fw_config(env)["system"]["pkg_repo_conf_path"].endswith("pfSense-repo-devel.conf")
    assert "pkg_switch_repo /usr/local/share/pfSense/pkg/repos/pfSense-repo-devel.conf" in (env["fw"] / "actions.log").read_text()
    # The update check after a switch downloads the new branch's catalogue first (pkg update -f) and waits
    # for a running routine check rather than being skipped by its lock.
    assert "lockf -s -t 600 /var/run/comsense_updates.lock" in (env["fw"] / "actions.log").read_text()
    assert "agent.php check-updates refresh" in (env["fw"] / "actions.log").read_text()
    agent(env, "run")  # reported at the next check-in
    with env["db"]() as db:
        assert db.get(Device, creds["device_id"]).inventory["update_branch"]["current"] == "Devel"
    tid = queue(TaskType.update_branch, {"branch": "Nightly"})
    agent(env, "run")
    assert task(tid).status == TaskStatus.failed and "does not offer" in task(tid).output

    tid = queue(TaskType.notifications, {"smtp": False})
    agent(env, "run")
    assert task(tid).status == TaskStatus.success
    assert not smtp_notifications_from_xml(pfsense_xml())["enabled"]
    queue(TaskType.notifications, {"smtp": True})
    agent(env, "run")
    assert smtp_notifications_from_xml(pfsense_xml())["enabled"]
    # The same, deployed as a configuration; unassigning puts back what the firewall had.
    with env["db"]() as db:
        notif = Policy(name="quiet", type=PolicyType.notifications, content={"smtp": False})
        db.add(notif)
        db.flush()
        db.add(PolicyAssignment(policy_id=notif.id, device_id=creds["device_id"]))
        db.commit()
    agent(env, "run")
    assert not smtp_notifications_from_xml(pfsense_xml())["enabled"]
    with env["db"]() as db:
        db.query(PolicyAssignment).filter(PolicyAssignment.policy_id == notif.id).delete()
        db.commit()
    agent(env, "run")
    assert smtp_notifications_from_xml(pfsense_xml())["enabled"]

    # 11. Surviving pfSense upgrades: the agent keeps a copy of its package and a boot script outside the
    #     package, and registers the script as a shellcmd; once in place, check-ins leave them alone.
    rec = env["fw"] / "db" / "recovery"
    copies = sorted(p.name for p in rec.glob("pfSense-pkg-ComSense-*.pkg"))
    from app.services.agentpkg import latest_package

    assert copies == [latest_package(env["dir"] / "data" / "downloads")["name"]]
    script = (rec / "recover.sh").read_text()
    assert "pkg-static add -f" not in script and '${PKG} add -f "${FILE}"' in script
    shellcmd = fw_config(env)["system"]["shellcmd"]
    assert shellcmd == ["/usr/sbin/daemon -f /bin/sh " + str(rec / "recover.sh")]
    writes = (env["fw"] / "actions.log").read_text().count("reinstall the agent at boot")
    assert writes == 1
    agent(env, "run")
    assert (env["fw"] / "actions.log").read_text().count("reinstall the agent at boot") == 1
    # Removing the package on purpose turns it off; a pfSense upgrade does not.
    agent(env, "disable-recovery")
    assert "shellcmd" not in fw_config(env)["system"] or fw_config(env)["system"]["shellcmd"] == []
    assert (rec / "disabled").exists() and not list(rec.glob("*.pkg"))

    # 11c. An upgrade is preceded by a backup of the configuration, kept (pinned) to roll back to: the
    #      server queues one ahead of it, and the agent uploads one itself before starting.
    set_fw_settings(env, allow_upgrade="on")
    tid = queue(TaskType.upgrade_system, {})
    agent(env, "run")
    with env["db"]() as db:
        tasks = db.scalars(select(Task).where(Task.device_id == creds["device_id"], Task.id >= tid - 1)
                           .order_by(Task.id)).all()
        assert [t.type for t in tasks[:2]] == [TaskType.backup, TaskType.upgrade_system]
        assert tasks[0].payload == {"reason": "pre_upgrade"} and tasks[0].status == TaskStatus.success
        assert "backed up before the upgrade" in tasks[1].output and tasks[1].status == TaskStatus.running
        pre = db.scalars(select(Backup).where(Backup.device_id == creds["device_id"], Backup.reason == "pre_upgrade")).all()
        assert pre and all(b.pinned for b in pre)
    actions = (env["fw"] / "actions.log").read_text()
    assert "pfSense-upgrade -y" in actions
    # The detached upgrade gets root's environment on its command line (pfSense-repoc needs the CA
    # certificates to reach Netgate), not by inheritance through mwexec and daemon(8).
    upgrade_line = next(line for line in actions.splitlines() if "pfSense-upgrade -y" in line)
    assert upgrade_line.startswith("mwexec: /usr/bin/env -i ") and "'PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin" in upgrade_line

    # 12. A disabled device is locked out.
    with env["db"]() as db:
        from app.models import DeviceStatus

        db.get(Device, creds["device_id"]).status = DeviceStatus.disabled
        db.commit()
    assert agent(env, "run") == "Check-in failed"
    with env["db"]() as db:
        assert db.get(Device, creds["device_id"]).last_seen_at is not None


def terminal_session(env, creds) -> None:
    import re
    import time

    import httpx
    from websockets.sync.client import connect

    from app.models import Device, Role, TerminalSession, TerminalStatus, User
    from app.security import hash_password
    from app.services import mfa

    set_fw_settings(env, allow_shell="on")
    agent(env, "run")
    secret = mfa.new_totp_secret()
    with env["db"]() as db:
        assert "shell" in db.get(Device, creds["device_id"]).capabilities
        user = User(username="e2e-admin", password_hash=hash_password("e2e-admin-password"), role=Role.admin)
        mfa.enable_totp(user, secret, mfa.current_step() - 2, "s" * 48)
        db.add(user)
        db.commit()

    web = f"http://127.0.0.1:{env['web_port']}"
    with httpx.Client(base_url=web, trust_env=False, follow_redirects=True) as http:
        def csrf(page: str) -> str:
            return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

        token = csrf(http.get("/login").text)
        http.post("/login", data={"username": "e2e-admin", "password": "e2e-admin-password", "csrf_token": token})
        code = mfa.totp_code(secret, mfa.current_step())
        r = http.post("/login/mfa", data={"code": code, "csrf_token": csrf(http.get("/login/mfa").text)})
        assert r.status_code == 200 and "/devices" in r.text, (r.url, re.findall(r"<main.*", r.text, re.S)[:1])
        page = http.get(f"/devices/{creds['device_id']}/terminal").text
        code = mfa.totp_code(secret, mfa.current_step() + 1)
        r = http.post(f"/devices/{creds['device_id']}/terminal", data={"code": code, "csrf_token": csrf(page)})
        sid = str(r.url).rsplit("/", 1)[1]
        assert 'data-live="1"' in r.text, r.text[:500]
        cookie = "; ".join(f"{k}={v}" for k, v in http.cookies.items())

    with connect(f"ws://127.0.0.1:{env['web_port']}/terminal/{sid}/ws",
                 additional_headers={"Origin": web, "Cookie": cookie}) as browser:
        assert json.loads(browser.recv(timeout=10))["s"] == "waiting"
        browser.send(json.dumps({"t": "r", "c": 120, "r": 40}))
        assert agent(env, "run") == "Checked in; ran 1 task(s)"  # the open_terminal task
        request = env["fw"] / "db" / "terminal" / f"{sid}.request"
        assert request.exists()  # comsense-agentd starts the helper after the cycle
        request.unlink()
        helper = subprocess.Popen(
            ["php", str(HARNESS), "terminal", sid],
            env={**os.environ, "CSFM_TEST_DIR": str(env["fw"]), "CSFM_AGENT_DIR": str(AGENT_DIR)},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            assert json.loads(browser.recv(timeout=20))["s"] == "connected"

            def run_and_wait(command: str, expect: str) -> str:
                browser.send(json.dumps({"t": "i", "d": command + "\r"}))
                seen = ""
                deadline = time.monotonic() + 15
                while expect not in seen:
                    assert time.monotonic() < deadline, seen
                    msg = browser.recv(timeout=15)
                    seen += msg.decode(errors="replace") if isinstance(msg, bytes) else ""
                return seen

            run_and_wait("echo ok-$((6*7))", "ok-42")
            run_and_wait("stty size", "40 120")
            browser.send(json.dumps({"t": "r", "c": 100, "r": 30}))
            time.sleep(0.5)
            run_and_wait("stty size", "30 100")
            run_and_wait("tty", "/dev/pts/")
            browser.send(json.dumps({"t": "i", "d": "exit\r"}))
            while True:
                msg = browser.recv(timeout=15)
                if isinstance(msg, str):
                    closed = json.loads(msg)
                    if closed.get("s") == "closed":
                        break
            assert closed["m"] == "The shell exited.", closed
        finally:
            out, _ = helper.communicate(timeout=20)
        assert helper.returncode == 0 and "The shell exited." in out, out

    with env["db"]() as db:
        ts = db.get(TerminalSession, sid)
        assert ts.status == TerminalStatus.closed and ts.bytes_out > 0
    assert not (env["fw"] / "db" / "terminal" / f"{sid}.tty").exists()
