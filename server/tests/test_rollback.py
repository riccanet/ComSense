from __future__ import annotations

import pytest
from conftest import auth, enroll, login, make_key
from sqlalchemy import select

from app.models import Alert, Device, Policy, PolicyAssignment, PolicyType, Task, TaskStatus, TaskType
from app.services.policy_examples import EXAMPLES


def _checkin(agent, token, **body):
    return agent.post("/api/agent/v1/checkin", json=body, headers=auth(token)).json()


@pytest.mark.changes
def test_rolled_back_change_raises_alert_and_is_not_resent(client, db, agent):
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    policy = Policy(name="breaker", type=PolicyType.aliases, content=EXAMPLES[PolicyType.aliases])
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, device_id=device.id))
    db.commit()
    token = creds["token"]

    [task] = _checkin(agent, token)["tasks"]
    assert task["type"] == "apply_policy"
    agent.post(f"/api/agent/v1/tasks/{task['id']}/result", json={"status": "success", "output": "Applied"},
               headers=auth(token))

    event = {
        "id": "abc123", "tasks": [task["id"]], "changes": "apply policy 'breaker' revision 1",
        "reason": "the management server was unreachable when the probation window ended",
        "changed_at": "2026-10-18T10:00:00+00:00", "rolled_back_at": "2026-10-18T10:05:00+00:00",
    }
    # The agent reports it (twice, as after a lost response); the change is not sent again.
    assert _checkin(agent, token, rollbacks=[event])["tasks"] == []
    assert _checkin(agent, token, rollbacks=[event], applied_policies={})["tasks"] == []
    db.expire_all()
    device = db.get(Device, creds["device_id"])
    assert device.rolled_back_policies == {str(policy.id): task["payload"]["policy"]["hash"]}
    alerts = db.scalars(select(Alert).where(Alert.device_id == device.id, Alert.key == "rollback:abc123")).all()
    assert len(alerts) == 1 and alerts[0].severity == "critical" and alerts[0].resolved_at is None
    assert "breaker" in alerts[0].message
    t = db.get(Task, task["id"])
    assert t.status == TaskStatus.failed and "Rolled back on the firewall" in t.output
    # A normal check-in does not resolve it: it is an event, not a condition.
    _checkin(agent, token)
    db.expire_all()
    assert db.get(Alert, alerts[0].id).resolved_at is None

    # The device page shows it; clearing resolves the alert and lets the change go out again.
    csrf = login(client)
    page = client.get(f"/devices/{device.id}").text
    assert "Rolled back changes" in page and "breaker" in page
    client.post(f"/devices/{device.id}/rollbacks/clear", data={"csrf_token": csrf})
    db.expire_all()
    assert db.get(Device, device.id).rolled_back_policies == {}
    assert db.get(Alert, alerts[0].id).resolved_at is not None
    [again] = _checkin(agent, token)["tasks"]
    assert again["type"] == "apply_policy"


@pytest.mark.changes
def test_new_revision_is_sent_after_a_rollback(client, db, agent):
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    policy = Policy(name="p", type=PolicyType.aliases, content=EXAMPLES[PolicyType.aliases])
    db.add(policy)
    db.flush()
    db.add(PolicyAssignment(policy_id=policy.id, device_id=device.id))
    db.commit()
    [task] = _checkin(agent, creds["token"])["tasks"]
    _checkin(agent, creds["token"], rollbacks=[{"id": "r1", "tasks": [task["id"]], "changes": "x", "reason": "y"}])
    db.expire_all()
    policy = db.get(Policy, policy.id)
    policy.content = {"aliases": [{"name": "OTHER", "type": "host", "address": ["192.0.2.1"]}]}
    policy.revision += 1
    db.commit()
    [fixed] = _checkin(agent, creds["token"])["tasks"]
    assert fixed["type"] == "apply_policy" and fixed["payload"]["policy"]["hash"] != task["payload"]["policy"]["hash"]


def test_rolled_back_removal_is_not_resent(client, db, agent):
    creds = enroll(agent, make_key(db))
    device = db.get(Device, creds["device_id"])
    task = Task(device_id=device.id, type=TaskType.remove_policy, payload={"policy_id": 7}, status=TaskStatus.success)
    db.add(task)
    db.commit()
    _checkin(agent, creds["token"], rollbacks=[{"id": "r2", "tasks": [task.id], "changes": "remove policy #7",
                                                "reason": "unreachable"}])
    db.expire_all()
    assert db.get(Device, device.id).rolled_back_policies == {"7": "remove"}
