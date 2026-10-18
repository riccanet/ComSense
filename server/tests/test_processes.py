from __future__ import annotations

import re

from conftest import auth, enroll, login, make_key


def test_process_snapshot_page(client, db, agent):
    login(client)
    creds = enroll(agent, make_key(db))
    page = client.get(f"/devices/{creds['device_id']}").text
    assert f'href="/devices/{creds["device_id"]}/processes"' in page
    assert "No process information yet" in client.get(f"/devices/{creds['device_id']}/processes").text

    snapshot = {"taken_at": "2026-10-18T19:40:00+00:00", "total": 120, "top": [
        {"pid": 10, "user": "root", "cpu": 1.5, "mem": 9.0, "rss_kb": 900000, "time": "1:00.00", "state": "S", "command": "/usr/local/bin/unbound"},
        {"pid": 20, "user": "root", "cpu": 42.0, "mem": 0.5, "rss_kb": 5000, "time": "9:00.00", "state": "R", "command": "/usr/local/bin/php-fpm <b>"},
    ]}
    agent.post("/api/agent/v1/checkin", json={"processes": snapshot, "system": {"hostname": "fw"}}, headers=auth(creds["token"]))

    page = client.get(f"/devices/{creds['device_id']}/processes").text
    assert "out of\n120 running" in page or "120 running" in page
    pids = re.findall(r'<td class="num mono">(\d+)</td>', page)
    assert pids == ["20", "10"]  # by CPU
    assert "&lt;b&gt;" in page  # command lines are escaped
    pids = re.findall(r'<td class="num mono">(\d+)</td>', client.get(f"/devices/{creds['device_id']}/processes?sort=mem").text)
    assert pids == ["10", "20"]  # by memory
