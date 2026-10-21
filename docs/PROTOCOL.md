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
 "applied_policies": {"3": "<sha256 of policy type+content>"},
 "change_guard": {"tasks": [42], "deadline": "…"},
 "rollbacks": [{"id": "9f1c…", "tasks": [42], "changes": "apply policy 'Office rules' revision 3",
                "reason": "the management server was unreachable when the probation window ended",
                "changed_at": "…", "rolled_back_at": "…"}]}
```

`change_guard` is present while a change is on probation. `rollbacks` lists rollbacks not yet
acknowledged; the agent drops them after a successful check-in, and the server ignores repeats by
`id`.

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
| `update_agent` | `{"version","file","sha256"}` | upgrade |
| `open_terminal` | `{"session"}` | shell |
| `nat_add` | `{"rule"}` (one port forward, as in a `port_forward` policy) | policy |
| `nat_remove` | `{"fingerprint","descr"}` | policy |
| `nat_edit` | `{"fingerprint","rule"}` | policy |
| `alias_add`, `alias_edit` | `{"alias"}` (one alias, as in an `aliases` policy) | policy |
| `alias_remove` | `{"name"}` | policy |
| `ddns_add` | `{"entry"}` (one Services > Dynamic DNS client) | policy |
| `ddns_edit` | `{"fingerprint","entry"}` (no `password`: keep the current one) | policy |
| `ddns_remove` | `{"fingerprint","descr"}` | policy |
| `update_branch` | `{"branch"}` (a name from the reported `update_branch.branches`) | upgrade |
| `notifications` | `{"smtp": true\|false}` | policy |

Tasks not picked up within 24 h (1 h for restores) expire. Tasks with no final result after their
timeout (15 min by default, 30 min for agent updates, 2 h for system upgrades) are marked failed.

`nat_add`, `nat_edit` and `nat_remove` are single changes from a firewall's page, run under the change
guard like policies. `nat_edit` and `nat_remove` name the port forward by a fingerprint: the first 16 hex digits of the SHA-256
of its interface, protocol, target, local-port, destination port and description joined with `\x1f`
(the server computes it from config.xml, the agent from its config). Port forwards owned by a
configuration are refused. `ddns_*` change one dynamic DNS client, named by a fingerprint of its
interface, provider, host name, domain name and description; a change clears the client's cached address
and runs `/etc/rc.dyndns.update` so the provider is updated at once. `update_branch` sets
`system/pkg_repo_conf_path` and calls `pkg_switch_repo()` as System > Update > Update Settings does,
then checks for updates on the new branch in the background. That check, and every `check_updates`
task, first downloads the repository catalogue again (`pkg update -f`, after pfSense's own metadata
refresh finishes): every branch's repository has the same name, so a plain update can keep the old
branch's catalogue and report no updates. Port ranges in rules and port forwards are written as
pfSense stores them (`8000-8100`; `8000:8100` is accepted and converted).

Check-ins also carry `update_branch` (`{"current", "branches": [{"name","descr","default"}]}`, from
`pkg_list_repos()`) and `ddns` (`{"clients": [{"fingerprint","cached_ip","updated"}], "providers":
[{"value","name"}]}`, the cached address per client and the providers that pfSense version supports). A linked filter rule is removed with its port forward, and an edit updates it
to match (settings the console does not show, such as NAT reflection, are kept). `alias_add`,
`alias_edit` and `alias_remove` change one alias by name: an edit keeps the name (rules refer to it),
removal is refused while a rule, port forward or other alias uses it, and aliases owned by a
configuration are refused. `notifications`
turns pfSense's own email notifications on or off (`notifications/smtp/disable`).

`update_agent` is the console's *Update agent* button. The agent downloads `file` from
`GET /agent-package/{file}`, refuses it unless its SHA-256 matches and `version` is newer than its own,
reports `running`, and installs it with `pkg-static add -f` (pkg refuses a plain `add` over an installed package) in a detached process that then restarts the
agent. The next cycle, run by the new agent, reports `success` (or `failed` with the pkg output).
Agent updates change no firewall configuration, so they are not held back by
`CSFM_ENABLE_FIREWALL_CHANGES`.

Agents up to 0.2.9 installed updates with a plain `pkg add`, which pkg up to 2.1 refuses over an
installed package. For those (by the version they report) the server serves a bootstrap package under
the same file name and checksum in the task: `comsense-agent-bootstrap`, which `pkg add` accepts as a
new package. It carries the real package, and its install script starts a detached job that waits for
pkg to finish, installs the real package with `pkg add -f`, removes the bootstrap and restarts the
agent. The job's command line names `agent-update.pkg`, so the old agent keeps waiting for it, and the
new agent reports the task's success.

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

## GET /wait?timeout=N

Long poll between check-ins. The server answers `{"wake": true}` as soon as a task is pending for the
device (for example after *Check now* in the console), or `{"wake": false}` after `N` seconds
(at most 55). The agent loops on this until its next check-in is due and checks in at once on a
wake. A server without this endpoint, or any error, makes the agent fall back to a plain sleep.

## WebSocket /terminal/{session}

The firewall end of a remote terminal, opened by the agent's terminal helper after an `open_terminal`
task (`Authorization: Bearer <device token>`). The session must belong to the device, be approved and
less than 2 minutes old. Server to agent: text `{"t":"i","d":"<keystrokes>"}` and
`{"t":"r","c":cols,"r":rows}` (the first `r` arrives once the admin's browser is connected). Agent to
server: binary frames with terminal output, and text `{"t":"x","m":"<reason>"}` before it ends the
session.

## GET /agent-package/{file}

The agent package (`pfSense-pkg-ComSense-<version>.pkg`) from the server's downloads directory, for
`update_agent` tasks. Same authentication as the rest of the API.

## GET /ping

`{"ok": true}`. Used to confirm connectivity after applying a policy.

## POST /token/rotate

Returns `{"token": "csfm_dev_…"}` and invalidates the old token.
