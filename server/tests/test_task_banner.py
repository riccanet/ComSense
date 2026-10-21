"""The green banner on a firewall's pages: tasks queued or running, with an upgrade's progress."""
from __future__ import annotations

from conftest import ALL_CAPS, auth, enroll, login, make_key

from app.models import Device, DeviceStatus, Task, TaskStatus, TaskType
from app.services.tasks import queue_task
from app.web.routes import _device_page_token


def test_banner_shows_queued_and_running_tasks_with_upgrade_progress(client, db, agent):
    login(client)
    creds = enroll(agent, make_key(db), capabilities=ALL_CAPS)
    did = creds["device_id"]
    assert "task-banner" not in client.get(f"/devices/{did}").text

    device = db.get(Device, did)
    queue_task(db, device, TaskType.check_updates, actor="t")
    db.commit()
    page = client.get(f"/devices/{did}").text
    assert "task-banner" in page and "Checking for updates" in page and "queued" in page
    assert "Checking for updates" in client.get(f"/devices/{did}/configuration").text

    # The agent takes the tasks and reports the upgrade's progress as it goes.
    queue_task(db, device, TaskType.upgrade_system, actor="t", changes_enabled=True)
    db.commit()
    tasks = agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).json()["tasks"]
    upgrade = next(t for t in tasks if t["type"] == "upgrade_system")
    before = _device_page_token(db, db.get(Device, did))
    agent.post(f"/api/agent/v1/tasks/{upgrade['id']}/result", headers=auth(creds["token"]), json={
        "status": "running", "output": "Installing packages (60 of 120) (69%)",
        "result": {"progress": {"percent": 69, "step": "Installing packages (60 of 120)"}}})
    db.expire_all()
    assert _device_page_token(db, db.get(Device, did)) != before  # the page reloads to show it
    page = client.get(f"/devices/{did}").text
    assert "Upgrading pfSense" in page and "Installing packages (60 of 120)" in page
    assert 'value="69"' in page and "69%" in page

    # Out of touch mid-upgrade: rebooting.
    db.get(Device, did).status = DeviceStatus.offline
    db.commit()
    page = client.get(f"/devices/{did}").text
    assert "Rebooting; waiting for the firewall to come back" in page and 'value="92"' in page

    # Finished tasks leave the banner.
    for t in db.query(Task).filter(Task.device_id == did):
        t.status = TaskStatus.success
    db.commit()
    assert "task-banner" not in client.get(f"/devices/{did}").text
