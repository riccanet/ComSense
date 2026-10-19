from __future__ import annotations

import gzip

from conftest import auth, enroll, login, make_key
from sqlalchemy import select

from app.models import AuditLog, Role, User
from app.security import hash_password
from app.services.configview import port_forwards_from_xml

CONFIG = b"""<?xml version="1.0"?>
<pfsense>
<version>23.3</version>
<system><user><name>admin</name><bcrypt-hash>$2y$10$secrethash</bcrypt-hash></user></system>
<aliases>
  <alias><name>Web_Servers</name><type>host</type><address>192.168.1.10 192.168.1.11</address>
    <descr>Front end</descr><detail>Primary||Standby</detail></alias>
  <alias><name>Office</name><type>network</type><address>10.0.0.0/24</address><descr></descr><detail></detail></alias>
</aliases>
<nat>
  <rule>
    <source><any></any></source>
    <destination><network>wanip</network><port>443</port></destination>
    <protocol>tcp</protocol><target>192.168.1.10</target><local-port>8443</local-port>
    <interface>wan</interface><descr>Web server</descr><associated-rule-id>pass</associated-rule-id>
  </rule>
  <rule>
    <source><address>OfficeHosts</address></source>
    <destination><network>wanip</network><port>3389</port></destination>
    <protocol>tcp</protocol><target>192.168.1.20</target><local-port>3389</local-port>
    <interface>wan</interface><descr>[CSFM] RDP</descr><comsense_policy>4</comsense_policy><disabled></disabled>
    <associated-rule-id>nat_5f00</associated-rule-id>
  </rule>
  <outbound><mode>automatic</mode></outbound>
</nat>
<openvpn><openvpn-server><tls>-----BEGIN OpenVPN Static key-----abc</tls></openvpn-server></openvpn>
</pfsense>
"""


def _device_with_backup(agent, db):
    creds = enroll(agent, make_key(db))
    r = agent.post("/api/agent/v1/backups", content=gzip.compress(CONFIG), headers=auth(creds["token"]))
    assert r.status_code == 200, r.text
    return creds["device_id"]


def test_port_forwards_are_read_from_config_xml():
    web, rdp = port_forwards_from_xml(CONFIG)
    assert web["destination"] == "wan address" and web["port"] == "443"
    assert (web["target"], web["local_port"], web["filter_rule"], web["managed"]) == ("192.168.1.10", "8443", "pass", False)
    assert rdp["source"] == "OfficeHosts" and rdp["disabled"] and rdp["managed"] and rdp["filter_rule"] == "linked"


def test_device_page_lists_inbound_nat(client, db, agent):
    login(client)
    did = _device_with_backup(agent, db)
    page = client.get(f"/devices/{did}/configuration").text
    assert "Inbound NAT policies" in page
    assert "192.168.1.10:8443" in page and "[CSFM] RDP" in page
    assert f'href="/devices/{did}/config"' in page


def test_view_config_hides_secrets(client, db, agent):
    login(client)
    did = _device_with_backup(agent, db)
    page = client.get(f"/devices/{did}/config").text
    assert "&lt;descr&gt;Web server&lt;/descr&gt;" in page  # escaped XML in a <pre>
    assert "secrethash" not in page and "Static key" not in page and "[hidden]" in page
    page = client.get(f"/devices/{did}/config?secrets=1").text
    assert "secrethash" in page and "Static key" in page
    assert db.scalar(select(AuditLog).where(AuditLog.action == "backup.viewed_secrets")) is not None


def test_view_config_permissions(client, db, agent):
    did = _device_with_backup(agent, db)
    db.add_all([
        User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator),
        User(username="v", password_hash=hash_password("viewer-password-1"), role=Role.viewer),
    ])
    db.commit()
    login(client, "v", "viewer-password-1")
    assert client.get(f"/devices/{did}/config").status_code == 403
    assert f'/devices/{did}/config"' not in client.get(f"/devices/{did}/configuration").text
    client.cookies.clear()
    login(client, "op", "operator-password-1")
    page = client.get(f"/devices/{did}/config?secrets=1").text
    assert "secrethash" not in page and "Show secrets" not in page  # operators never see secrets on screen
