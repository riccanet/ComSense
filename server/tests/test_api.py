"""The REST API (/api/v1) and the MCP server, both authenticated with API keys."""
from __future__ import annotations

import re
from datetime import timedelta

import pytest
from conftest import auth, enroll, login, make_key
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api import rest
from app.mcp_server import auth_failures as mcp_auth_failures
from app.mcp_server import create_mcp_app
from app.models import Alert, ApiKey, Organization, Role, Task, TaskType, utcnow
from app.services import apiops


@pytest.fixture(autouse=True)
def _reset_limiters():
    rest.auth_failures.reset()
    mcp_auth_failures.reset()


def _key(db, role: Role = Role.viewer, **kwargs) -> str:
    key, value = apiops.create_key(db, f"{role.value} key", role, "admin", None)
    for k, v in kwargs.items():
        setattr(key, k, v)
    db.commit()
    return value


def _bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def _fleet(db, agent, settings):
    acme = Organization(name="Acme")
    db.add(acme)
    db.commit()
    one = enroll(agent, make_key(db, organization_id=acme.id), system={"hostname": "fw-acme", "unique_id": "a1"})
    two = enroll(agent, make_key(db), system={"hostname": "fw-loose", "unique_id": "b1"})
    current = apiops.latest_package(settings.data_dir / "downloads")["version"]
    agent.post("/api/agent/v1/checkin", json={"agent_version": current}, headers=auth(two["token"]))
    agent.post("/api/agent/v1/checkin", json={"agent_version": "0.2.7", "interfaces": [
        {"name": "wan", "ipaddr": "203.0.113.9", "gateway": "203.0.113.1"}]}, headers=auth(one["token"]))
    return acme, one["device_id"], two["device_id"]


def test_api_keys_are_created_in_settings_and_shown_once(client, db):
    csrf = login(client)
    assert "API keys" in client.get("/settings").text or "/settings/api-keys" in client.get("/settings/general").text
    r = client.post("/settings/api-keys", data={"name": "n8n", "role": "operator", "expires_days": "30",
                                                "csrf_token": csrf})
    value = re.search(r"(csfm_api_[A-Za-z0-9_-]+)", r.text).group(1)
    key = db.scalar(select(ApiKey))
    assert key.role == Role.operator and key.expires_at is not None and key.key_hash != value
    assert value not in client.get("/settings/api-keys").text  # only once
    assert client.get("/api/v1/customers", headers=_bearer(value)).status_code == 200
    client.post(f"/settings/api-keys/{key.id}/revoke", data={"csrf_token": csrf})
    assert client.get("/api/v1/customers", headers=_bearer(value)).status_code == 401


def test_rest_api_reads(client, db, agent, settings):
    acme, acme_fw, loose_fw = _fleet(db, agent, settings)
    key = _bearer(_key(db))
    assert client.get("/api/v1/firewalls").status_code == 401
    assert client.get("/api/v1/firewalls", headers=_bearer("csfm_api_wrong")).status_code == 401
    firewalls = client.get("/api/v1/firewalls", headers=key).json()
    assert [f["name"] for f in firewalls] == ["fw-acme", "fw-loose"]  # by customer, unassigned last
    assert firewalls[0]["customer"] == {"id": acme.id, "name": "Acme"} and firewalls[0]["wan_ips"] == ["203.0.113.9"]
    assert firewalls[0]["agent_update_available"] is True
    assert [f["name"] for f in client.get("/api/v1/firewalls", headers=key, params={"customer_id": acme.id}).json()] \
        == ["fw-acme"]
    assert [f["name"] for f in client.get("/api/v1/firewalls", headers=key, params={"agent_outdated": True}).json()] \
        == ["fw-acme"]
    detail = client.get(f"/api/v1/firewalls/{acme_fw}", headers=key).json()
    assert detail["interfaces"][0]["ipaddr"] == "203.0.113.9" and "token_hash" not in detail
    assert client.get("/api/v1/firewalls/nope", headers=key).status_code == 404
    assert client.get("/api/v1/customers", headers=key).json()[0]["firewalls"] == 1
    assert client.get(f"/api/v1/customers/{acme.id}", headers=key).json()["firewalls"][0]["id"] == acme_fw
    assert client.get("/api/v1/tasks-available", headers=key).json()["reboot"]
    schema = client.get("/api/v1/openapi.json").json()
    assert "/firewalls/{firewall_id}/tasks" in schema["paths"]


def test_viewer_keys_cannot_change_anything(client, db, agent, settings):
    _, acme_fw, _ = _fleet(db, agent, settings)
    key = _bearer(_key(db))
    r = client.post(f"/api/v1/firewalls/{acme_fw}/tasks", headers=key, json={"task": "backup"})
    assert r.status_code == 403 and "viewer" in r.json()["detail"]
    assert client.put(f"/api/v1/firewalls/{acme_fw}/customer", headers=key, json={"customer_id": None}).status_code == 403


def test_operator_keys_queue_tasks_with_the_console_checks(client, db, agent, settings):
    acme, acme_fw, loose_fw = _fleet(db, agent, settings)
    key = _bearer(_key(db, Role.operator))
    r = client.post(f"/api/v1/firewalls/{acme_fw}/tasks", headers=key, json={"task": "backup"})
    assert r.status_code == 201 and r.json()["type"] == "backup" and r.json()["created_by"] == "api:operator key"
    task_id = r.json()["id"]
    assert client.get(f"/api/v1/tasks/{task_id}", headers=key).json()["status"] == "pending"
    assert [t["id"] for t in client.get(f"/api/v1/firewalls/{acme_fw}/tasks", headers=key).json()] == [task_id]
    # Reboots need the firewall-changes switch, as in the console.
    r = client.post(f"/api/v1/firewalls/{acme_fw}/tasks", headers=key, json={"task": "reboot"})
    assert r.status_code == 409 and "Coming soon" in r.json()["detail"]
    assert client.post(f"/api/v1/firewalls/{acme_fw}/tasks", headers=key, json={"task": "rm -rf"}).status_code == 400
    r = client.post(f"/api/v1/firewalls/{acme_fw}/tasks", headers=key, json={"task": "check_now"})
    assert r.json()["type"] == "refresh_inventory"
    r = client.post(f"/api/v1/firewalls/{acme_fw}/tasks", headers=key, json={"task": "update_agent"})
    assert r.status_code == 201 and db.scalar(select(Task).where(Task.type == TaskType.update_agent)) is not None
    # Customers and alerts.
    r = client.put(f"/api/v1/firewalls/{loose_fw}/customer", headers=key, json={"customer_id": acme.id})
    assert r.json()["customer"]["name"] == "Acme"
    alert = Alert(device_id=acme_fw, key="gw", severity="warning", message="Gateway WAN is down")
    db.add(alert)
    db.commit()
    assert client.get("/api/v1/alerts", headers=key).json()[0]["message"] == "Gateway WAN is down"
    assert client.post(f"/api/v1/alerts/{alert.id}/acknowledge", headers=key).json()["acknowledged_by"] == "api:operator key"


def test_expired_keys_and_repeated_failures_are_refused(client, db):
    expired = _key(db, expires_at=utcnow() - timedelta(minutes=1))
    assert client.get("/api/v1/customers", headers=_bearer(expired)).status_code == 401
    for _ in range(20):
        client.get("/api/v1/customers", headers=_bearer("csfm_api_guess"))
    assert client.get("/api/v1/customers", headers=_bearer(_key(db))).status_code == 429


def _mcp(c: TestClient, key: str | None, method: str, params: dict | None = None, id_: int = 1):
    headers = {"accept": "application/json, text/event-stream", "content-type": "application/json",
               "mcp-protocol-version": "2025-06-18"}
    if key:
        headers["authorization"] = f"Bearer {key}"
    return c.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}})


def test_mcp_server(client, db, agent, settings):
    acme, acme_fw, _ = _fleet(db, agent, settings)
    viewer, operator = _key(db), _key(db, Role.operator)
    with TestClient(create_mcp_app(settings), base_url="http://mcp.test") as c:
        assert _mcp(c, None, "tools/list").status_code == 401
        init = _mcp(c, viewer, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                              "clientInfo": {"name": "test", "version": "1"}})
        assert init.status_code == 200 and init.json()["result"]["serverInfo"]["name"] == "ComSense Firewall Manager"
        tools = {t["name"]: t for t in _mcp(c, viewer, "tools/list").json()["result"]["tools"]}
        assert {"list_firewalls", "get_firewall", "run_task", "list_alerts", "acknowledge_alert"} <= set(tools)
        assert tools["list_firewalls"]["annotations"]["readOnlyHint"] is True
        assert tools["run_task"]["annotations"]["destructiveHint"] is True

        listed = _mcp(c, viewer, "tools/call", {"name": "list_firewalls", "arguments": {}}).json()["result"]
        assert not listed["isError"] and [f["name"] for f in listed["structuredContent"]["result"]] == ["fw-acme", "fw-loose"]
        denied = _mcp(c, viewer, "tools/call", {"name": "run_task",
                                                "arguments": {"firewall_id": acme_fw, "task": "backup"}}).json()["result"]
        assert denied["isError"] and "viewer" in denied["content"][0]["text"]
        queued = _mcp(c, operator, "tools/call", {"name": "run_task",
                                                  "arguments": {"firewall_id": acme_fw, "task": "backup"}}).json()["result"]
        assert not queued["isError"] and queued["structuredContent"]["type"] == "backup"
        task = db.scalar(select(Task).where(Task.type == TaskType.backup))
        assert task.created_by == "api:operator key"
        missing = _mcp(c, viewer, "tools/call", {"name": "get_firewall", "arguments": {"firewall_id": "nope"}}).json()
        assert missing["result"]["isError"] and "No firewall" in missing["result"]["content"][0]["text"]
