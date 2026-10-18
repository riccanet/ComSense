# Agent protocol

All endpoints are under `https://<server>:<agent port>/api/agent/v1` (port 10443 by default). The agent
listener is separate from the web console and serves nothing else. Agents authenticate the server by
pinning its public key (`CURLOPT_PINNEDPUBLICKEY`), or by CA verification when the operator installed
their own certificate.

Endpoints exchange JSON (except backup bodies), and
except `/enroll` require `Authorization: Bearer <device token>`. Errors are `{"detail": "..."}` with
a 4xx status. 401 means the token is unknown (the agent asks for re-enrollment); 403 means the device
is disabled or still awaiting approval; 429 means the source address sent 20 bad tokens within
10 minutes and is refused until that window passes.

## Enrollment codes

`csfm1.` followed by base64url (no padding) of `{"url": "<agent URL>", "key": "<enrollment key>",
"pin": "<base64 SHA-256 of the server SubjectPublicKeyInfo>"}`. `pin` is omitted when the agent
listener uses an operator-supplied certificate.

## POST /enroll

```json
{"enrollment_key": "csfm_enr_…", "agent_version": "0.1.0",
 "system": {"hostname": "fw1.example.com", "edition": "ce", "version": "2.7.2-RELEASE",
            "platform": "…", "serial": "…", "unique_id": "…"},
 "capabilities": ["backup", "policy"]}
```

Response: `{"device_id": "<uuid>", "token": "csfm_dev_…", "status": "online"|"pending",
"checkin_interval": 60}`.

The key must exist, not be revoked or expired, and have uses left. A firewall that enrolls again
with the same `unique_id` into the same customer is reattached to its existing record and its old
token stops working. Limited to 10 attempts per source address per 10 minutes.

## POST /checkin

Body: the agent's report.

```json
{"agent_version": "0.1.0", "capabilities": [...], "system": {...},
 "metrics": {"cpu_pct": 3.1, "mem_pct": 41.0, "disk_pct": 22.5, "load": [0.1, 0.2, 0.2],
             "states": 812, "states_max": 400000, "uptime": 86400},
 "interfaces": [{"name": "wan", "descr": "WAN", "if": "igb0", "status": "up", "ipaddr": "…", ...}],
 "gateways": [{"name": "WAN_DHCP", "status": "online", "delay": "1.2ms", "loss": "0.0%", ...}],
 "services": [{"name": "unbound", "description": "DNS Resolver", "running": true}],
 "carp": [], "packages": [{"name": "pfSense-pkg-…", "version": "…"}],
 "updates": {"installed_version": "…", "version": "…", "update_available": false, "packages": []},
 "config": {"sha256": "…", "revision": "admin@10.0.0.5: …", "time": 1700000000},
 "applied_policies": {"3": "<sha256 of policy type+content>"}}
```

Response:

```json
{"status": "online", "checkin_interval": 60, "server_time": "…",
 "tasks": [{"id": 42, "type": "apply_policy", "payload": {...}}],
 "upload_backup": true, "rotate_token": true}
```

`upload_backup` is present when the reported config hash differs from the newest stored backup.
`rotate_token` is present when the token is older than 30 days. Pending (unapproved) devices receive
no tasks.

## Task types

| type | payload | permission on firewall |
| --- | --- | --- |
| `backup` | `{"reason"}` | backup |
| `apply_policy` | `{"policy": {"id","name","type","revision","hash","content"}}` | policy |
| `remove_policy` | `{"policy_id"}` | policy |
| `check_updates`, `refresh_inventory` | | always |
| `upgrade_system`, `upgrade_packages` | | upgrade |
| `install_package`, `remove_package` | `{"package"}` | packages |
| `restart_service` | `{"service"}` | services |
| `restore_backup` | `{"backup_id","sha256"}` | restore |
| `reboot` | | reboot |

Tasks not picked up within 24 h (1 h for restores) expire. Tasks with no final result after their
timeout (15 min by default, 2 h for system upgrades) are marked failed.

## POST /tasks/{id}/result

`{"status": "running"|"success"|"failed", "output": "…", "result": {...}}`. `running` may be sent
first for long tasks (system upgrades) and followed by a final status later.

## POST /backups

Body: gzip-compressed `config.xml`. Headers: `Content-Type: application/gzip`,
`X-CSFM-SHA256` (of the uncompressed file), `X-CSFM-Reason`, optional `X-CSFM-Task-ID`.
Response: `{"backup_id", "sha256", "created"}`; `created` is false when an identical backup exists.

## GET /backups/{id}

Returns the gzip-compressed backup with an `X-CSFM-SHA256` header, only while a `restore_backup` task
for that backup is in flight for the calling device.

## GET /ping

`{"ok": true}`. Used to confirm connectivity after applying a policy.

## POST /token/rotate

Returns `{"token": "csfm_dev_…"}` and invalidates the old token.
