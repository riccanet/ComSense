from __future__ import annotations

import pytest
from conftest import auth, enroll, make_key

from app.models import Device, Policy, PolicyAssignment, PolicyType, Task, TaskStatus, TaskType
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


def _checkin(client, token, applied=None):
    body = {"applied_policies": applied or {}}
    return client.post("/api/agent/v1/checkin", json=body, headers=auth(token)).json()["tasks"]


def test_policy_reconciliation(client, db):
    creds = enroll(client, make_key(db))
    device = db.get(Device, creds["device_id"])
    policy = Policy(name="aliases", type=PolicyType.aliases, content=EXAMPLES[PolicyType.aliases])
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, all_devices=True))
    db.commit()

    tasks = _checkin(client, creds["token"])
    assert [t["type"] for t in tasks] == ["apply_policy"]
    sent = tasks[0]
    digest = sent["payload"]["policy"]["hash"]
    # While in flight, nothing new is queued.
    assert _checkin(client, creds["token"]) == []

    client.post(f"/api/agent/v1/tasks/{sent['id']}/result", json={"status": "success"}, headers=auth(creds["token"]))
    assert _checkin(client, creds["token"], {str(policy.id): digest}) == []

    # Editing the policy produces a new apply task with the new hash.
    policy.content = {**policy.content, "remove_unlisted": False}
    db.commit()
    tasks = _checkin(client, creds["token"], {str(policy.id): digest})
    assert len(tasks) == 1 and tasks[0]["payload"]["policy"]["hash"] != digest
    client.post(f"/api/agent/v1/tasks/{tasks[0]['id']}/result", json={"status": "success"}, headers=auth(creds["token"]))
    new_digest = tasks[0]["payload"]["policy"]["hash"]

    # Removing the assignment asks the agent to clean up.
    db.query(PolicyAssignment).delete()
    db.commit()
    tasks = _checkin(client, creds["token"], {str(policy.id): new_digest})
    assert [(t["type"], t["payload"]) for t in tasks] == [("remove_policy", {"policy_id": policy.id})]

    db.expire_all()
    assert db.get(Device, device.id).applied_policies == {str(policy.id): new_digest}


def test_policy_needs_capability(client, db):
    creds = enroll(client, make_key(db), capabilities=["backup"])
    policy = Policy(name="sys", type=PolicyType.system, content={"timezone": "UTC"})
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, device_id=creds["device_id"]))
    db.commit()
    assert _checkin(client, creds["token"]) == []
    assert db.query(Task).filter(Task.type == TaskType.apply_policy).count() == 0


def test_pending_task_superseded_by_new_revision(client, db):
    creds = enroll(client, make_key(db))
    device = db.get(Device, creds["device_id"])
    policy = Policy(name="sys", type=PolicyType.system, content={"timezone": "UTC"})
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, device_id=device.id))
    db.commit()

    from app.services.policies import reconcile_device_policies

    first = reconcile_device_policies(db, device)
    db.commit()
    policy.content = {"timezone": "Europe/Paris"}
    db.commit()
    second = reconcile_device_policies(db, device)
    db.commit()
    assert db.get(Task, first[0].id).status == TaskStatus.cancelled
    assert second[0].payload["policy"]["content"] == {"timezone": "Europe/Paris"}
