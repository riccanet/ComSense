from __future__ import annotations

import pytest
from conftest import auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Device, Policy, PolicyAssignment, PolicyType, Role, Task, TaskStatus, TaskType, User
from app.security import hash_password
from app.services.policies import PolicyError, validate_policy
from app.services.policy_examples import EXAMPLES


@pytest.mark.parametrize("ptype", list(PolicyType))
def test_examples_are_valid(ptype):
    validate_policy(ptype, EXAMPLES[ptype])


@pytest.mark.parametrize(
    "ptype,content",
    [
        (PolicyType.aliases, {"aliases": [{"name": "bad name!", "type": "host", "address": []}]}),
        (PolicyType.aliases, {"aliases": [{"name": "A", "type": "bogus", "address": []}]}),
        (PolicyType.firewall_rules, {"rules": [{"interface": "eth0; rm -rf /", "type": "pass"}]}),
        (PolicyType.firewall_rules, {"rules": [{"interface": "wan", "source": {"address": "not an ip"}}]}),
        (PolicyType.system, {"dnsservers": ["8.8.8.8", "nope"]}),
        (PolicyType.system, {"shell": "x"}),
        (PolicyType.packages, {"install": ["curl"]}),
        (PolicyType.config_set, {"items": [{"path": "system/user/0/password", "value": "x"}]}),
        (PolicyType.config_set, {"items": [{"path": "installedpackages/comsense/config", "delete": True}]}),
        (PolicyType.config_set, {"items": [{"path": "../etc", "value": "x"}]}),
    ],
)
def test_invalid_policies_rejected(ptype, content):
    with pytest.raises(PolicyError):
        validate_policy(ptype, content)


def _checkin(agent, token, applied=None):
    body = {"applied_policies": applied or {}}
    return agent.post("/api/agent/v1/checkin", json=body, headers=auth(token)).json()["tasks"]


@pytest.mark.changes
def test_policy_reconciliation(client, db, agent):
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    policy = Policy(name="aliases", type=PolicyType.aliases, content=EXAMPLES[PolicyType.aliases])
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, all_devices=True))
    db.commit()

    tasks = _checkin(agent, creds["token"])
    assert [t["type"] for t in tasks] == ["apply_policy"]
    sent = tasks[0]
    digest = sent["payload"]["policy"]["hash"]
    # While in flight, nothing new is queued.
    assert _checkin(agent, creds["token"]) == []

    agent.post(f"/api/agent/v1/tasks/{sent['id']}/result", json={"status": "success"}, headers=auth(creds["token"]))
    assert _checkin(agent, creds["token"], {str(policy.id): digest}) == []

    # Editing the policy produces a new apply task with the new hash.
    policy.content = {**policy.content, "remove_unlisted": False}
    db.commit()
    tasks = _checkin(agent, creds["token"], {str(policy.id): digest})
    assert len(tasks) == 1 and tasks[0]["payload"]["policy"]["hash"] != digest
    agent.post(f"/api/agent/v1/tasks/{tasks[0]['id']}/result", json={"status": "success"}, headers=auth(creds["token"]))
    new_digest = tasks[0]["payload"]["policy"]["hash"]

    # Removing the assignment asks the agent to clean up.
    db.query(PolicyAssignment).delete()
    db.commit()
    tasks = _checkin(agent, creds["token"], {str(policy.id): new_digest})
    assert [(t["type"], t["payload"]) for t in tasks] == [("remove_policy", {"policy_id": policy.id})]

    db.expire_all()
    assert db.get(Device, device.id).applied_policies == {str(policy.id): new_digest}


def test_policy_needs_capability(client, db, agent):
    creds = enroll(agent, make_key(db), capabilities=["backup"])
    policy = Policy(name="sys", type=PolicyType.system, content={"timezone": "UTC"})
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, device_id=creds["device_id"]))
    db.commit()
    assert _checkin(agent, creds["token"]) == []
    assert db.query(Task).filter(Task.type == TaskType.apply_policy).count() == 0


def test_pending_task_superseded_by_new_revision(client, db, agent):
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    policy = Policy(name="sys", type=PolicyType.system, content={"timezone": "UTC"})
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, device_id=device.id))
    db.commit()

    from app.services.policies import reconcile_device_policies

    first = reconcile_device_policies(db, device, changes_enabled=True)
    db.commit()
    policy.content = {"timezone": "Europe/Paris"}
    db.commit()
    second = reconcile_device_policies(db, device, changes_enabled=True)
    db.commit()
    assert db.get(Task, first[0].id).status == TaskStatus.cancelled
    assert second[0].payload["policy"]["content"] == {"timezone": "Europe/Paris"}


@pytest.mark.parametrize("path", [
    "system", "system/user", "system/user/0/bcrypt-hash", "system/shellcmd", "system/earlyshellcmd",
    "installedpackages", "installedpackages/comsense/config", "installedpackages/filer", "cron", "cron/item",
    "cert", "ca",
])
def test_config_set_refuses_protected_paths_and_everything_above_them(path):
    with pytest.raises(PolicyError, match="protected"):
        validate_policy(PolicyType.config_set, {"items": [{"path": path, "value": "x"}]})


def test_config_set_allows_ordinary_paths():
    validate_policy(PolicyType.config_set, {"items": [{"path": "system/timeservers", "value": "pool.ntp.org"},
                                                      {"path": "installedpackages/acme/enable", "delete": True}]})


def test_only_admins_write_raw_config_set_configurations(client, db):
    db.add(User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator))
    db.commit()
    csrf = login(client, "op", "operator-password-1")
    r = client.post("/configurations", data={"type": "config_set", "name": "x", "csrf_token": csrf,
                                              "content": '{"items": [{"path": "system/timeservers", "value": "a"}]}'})
    assert r.status_code == 403
    r = client.post("/configurations", data={"type": "notifications", "name": "quiet", "smtp": "off", "csrf_token": csrf})
    assert r.status_code == 200 and db.scalar(select(Policy).where(Policy.name == "quiet")) is not None


def test_alias_entries_as_typed_or_pasted():
    from app.services.policies import parse_alias_entries

    assert parse_alias_entries("10.0.0.5 10.0.0.6 Front desk") == (["10.0.0.5", "10.0.0.6"], ["Front desk", "Front desk"])
    assert parse_alias_entries("10.0.0.5, 10.0.0.6;10.0.0.7\n\n10.0.0.5 dup") == (
        ["10.0.0.5", "10.0.0.6", "10.0.0.7"], ["", "", ""])
    # Words in a description are never taken for entries, even hex-looking ones; ports and ranges are.
    assert parse_alias_entries("printer.local cafe bad 2nd floor") == (["printer.local"], ["cafe bad 2nd floor"])
    assert parse_alias_entries("80 443 8000:8100 web") == (["80", "443", "8000:8100"], ["web", "web", "web"])
    assert parse_alias_entries("fd00::1 fd00::2/64 lab")[0] == ["fd00::1", "fd00::2/64"]
