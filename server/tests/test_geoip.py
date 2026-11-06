"""pfBlocker GeoIP configurations (one region permitted as an alias, every other region off), copied from a
firewall, with the MaxMind key kept secret; and the fleet's port forwards open to anyone, limited to the alias."""
from __future__ import annotations

import gzip

import pytest
from conftest import auth, enroll, login, make_key
from sqlalchemy import select
from test_config_view import CONFIG

from app.models import Policy, PolicyType, Task, TaskType
from app.services import geoip
from app.services.tasks import task_to_wire

PFB = b"""<installedpackages>
  <pfblockerngipsettings><config><maxmind_account>282790</maxmind_account><maxmind_key>Secret_Key_123</maxmind_key>
    <inbound_interface>wan,opt1</inbound_interface></config></pfblockerngipsettings>
  <pfblockerngnorthamerica><config><action>Alias_Permit</action><countries4>US,US_rep</countries4><countries6>US</countries6></config></pfblockerngnorthamerica>
  <pfblockerngeurope><config><action>Disabled</action></config></pfblockerngeurope>
</installedpackages>
<aliases><alias><name>pfB_NAmerica_v4</name><type>urltable</type></alias></aliases>"""


def _firewall(agent, db, name, with_pfb=True):
    creds = enroll(agent, make_key(db), system={"hostname": name, "unique_id": name})
    xml = CONFIG.replace(b"</pfsense>", PFB + b"</pfsense>") if with_pfb else CONFIG
    r = agent.post("/api/agent/v1/backups", content=gzip.compress(xml), headers=auth(creds["token"]))
    assert r.status_code == 200, r.text
    return creds


def test_copied_from_a_firewall_with_the_key_encrypted(client, db, agent, settings):
    did = _firewall(agent, db, "pk")["device_id"]
    login(client)
    page = client.get(f"/configurations/new?type=geoip&source={did}").text
    assert "Copied from pk" in page and 'value="US, US_rep"' in page and 'value="282790"' in page
    assert "Secret_Key_123" not in page and "saved; leave empty to keep it" in page
    # The key is hidden when the firewall's configuration is read, too.
    from app.services import apiops

    ipset = apiops.get_config(db, settings, did, "installedpackages/pfblockerngipsettings/config", depth=3)["value"]
    assert ipset[0]["maxmind_key"] == "[hidden]" and ipset[0]["maxmind_account"] == "282790"


@pytest.mark.changes
def test_saved_encrypted_kept_when_left_empty_and_sent_to_the_firewall_in_clear(client, db, agent, settings):
    csrf = login(client)
    form = {"csrf_token": csrf, "type": "geoip", "name": "US only", "permit": "northamerica",
            "countries4": "US, US_rep", "countries6": "US", "maxmind_account": "282790", "maxmind_key": ""}
    r = client.post("/configurations", data=form)
    assert r.status_code == 400 and "MaxMind license key" in r.text
    r = client.post("/configurations", data={**form, "maxmind_key": "Secret_Key_123"})
    policy = db.scalar(select(Policy).where(Policy.type == PolicyType.geoip))
    assert policy.content["maxmind_key"].startswith("enc:") and "Secret_Key_123" not in str(policy.content)
    assert policy.content["countries4"] == ["US", "US_rep"]
    assert "Secret_Key_123" not in client.get(f"/configurations/{policy.id}").text
    assert "Permit US as pfB_NAmerica_v4" in client.get("/configurations/geoip").text
    # Saved again without a key: the stored one stays.
    stored = policy.content["maxmind_key"]
    client.post(f"/configurations/{policy.id}", data={**form, "countries4": "US, US_rep, CA", "enabled": "true"})
    db.refresh(policy)
    assert policy.content["maxmind_key"] == stored and "CA" in policy.content["countries4"]
    # Only what goes to the firewall has it in clear.
    from app.services.policies import policy_payload

    task = Task(device_id="x", type=TaskType.apply_policy, payload=policy_payload(policy))
    assert task_to_wire(task, settings.secret_key)["payload"]["policy"]["content"]["maxmind_key"] == "Secret_Key_123"
    assert "Secret_Key_123" not in str(task.payload)


def test_validation():
    good = {"permit": "northamerica", "countries4": ["US"], "countries6": [], "maxmind_account": "1",
            "maxmind_key": "enc:x"}
    geoip.validate(good)
    for bad in ({"permit": "mars"}, {"countries4": ["usa"]}, {"countries4": []}, {"maxmind_account": "abc"},
                {"maxmind_key": "plain"}):
        with pytest.raises(ValueError):
            geoip.validate({**good, **bad})


@pytest.mark.changes
def test_open_port_forwards_limited_to_the_alias(client, db, agent):
    ready = _firewall(agent, db, "fw-ready")["device_id"]
    _firewall(agent, db, "fw-no-alias", with_pfb=False)
    csrf = login(client)
    page = client.get("/configurations/nat/open").text
    # The open "Web server" forward on both; the [CSFM] one (an alias source, a ComSense configuration) on neither.
    assert page.count("Web server") == 2 and "RDP" not in page
    assert page.count('name="forward"') == 1  # only where pfB_NAmerica_v4 exists
    value = next(v for v in page.split('name="forward" value="')[1:]).split('"')[0]
    assert value.startswith(ready)
    r = client.post("/configurations/nat/open", data={"csrf_token": csrf, "forward": [value, "bogus:0000"]})
    assert "Limiting 1 port forward(s) to pfB_NAmerica_v4" in r.text and "Not changed (1)" in r.text
    task = db.scalar(select(Task).where(Task.type == TaskType.nat_edit))
    assert task.device_id == ready and task.payload["rule"]["source"] == {"address": "pfB_NAmerica_v4"}
