# Configurations (policies)

The console's **Configurations** area manages aliases, firewall rules and inbound NAT (port forwards)
with forms; system settings, packages and raw config values are JSON documents under *Advanced*. Each
one is stored as a policy of the type below.

> Configurations can always be built and assigned, but they are only sent to firewalls while the server
> runs with `CSFM_ENABLE_FIREWALL_CHANGES=true` and the firewall allows *Policies* in Services >
> ComSense Agent.

**Firewall groups** (Configurations > Firewall groups) are named sets of firewalls from any customers.
A configuration assigned to a group applies to every firewall in it; adding or removing a firewall
from the group applies or removes the group's configurations at its next check-in.

A policy is a typed JSON document. Assign it to a firewall, a firewall group, a customer (all of its firewalls) or all firewalls; each
assigned firewall applies it at its next check-in and reports a hash of what it applied, which the
console shows as *in sync* or *pending*. Editing a policy creates a new revision that is pushed again.
Unassigning or deleting it makes the firewall remove what that policy created (and restore values
it changed), and nothing else.

The server validates every document before saving, and the agent validates again before applying.
Every policy apply and removal runs under the agent's change guard: if the firewall cannot reach the
server right after the change, or when its 5-minute probation ends, the previous configuration is
restored, the console raises an alert and that revision is not sent again until cleared. See
[Automatic rollback](AGENT.md#automatic-rollback-failback).

## aliases

```json
{
  "remove_unlisted": true,
  "adopt_existing": false,
  "aliases": [
    {"name": "CSFM_Mgmt_Hosts", "type": "host", "address": ["203.0.113.10", "203.0.113.11"],
     "detail": ["NOC primary", "NOC secondary"], "descr": "Management hosts"},
    {"name": "CSFM_Blocklist", "type": "urltable", "address": ["https://example.com/list.txt"], "updatefreq": "1"}
  ]
}
```

* `type`: `host`, `network`, `port`, `url`, `urltable`, `url_ports`, `urltable_ports`.
* Names: letters, digits and `_`, up to 31 characters.
* An alias that already exists on the firewall and was not created by this policy is not touched
  unless `adopt_existing` is true. Two policies cannot manage the same alias.
* `remove_unlisted` (default true): aliases dropped from a later revision are deleted.
* Aliases still referenced by rules or NAT are never deleted; the task output says which were kept.

## firewall_rules

```json
{
  "position": "top",
  "rules": [
    {"interface": "wan", "type": "block", "ipprotocol": "inet", "protocol": "any",
     "source": {"address": "CSFM_Blocklist"}, "destination": {"any": true},
     "descr": "Block known-bad networks", "log": true},
    {"interface": "wan", "type": "pass", "protocol": "tcp",
     "source": {"address": "CSFM_Mgmt_Hosts"}, "destination": {"network": "wanip", "port": "443"},
     "descr": "NOC to WebGUI"},
    {"interface": "floating", "floating_interfaces": ["wan", "opt1"], "direction": "in",
     "type": "block", "source": {"address": "198.51.100.0/24"}, "descr": "Floating block"}
  ]
}
```

* `interface`: `wan`, `lan`, `optN`, `floating`, `ipsec`, `openvpn`, `wireguard`, `enc0`.
* `type`: `pass`, `block`, `reject`. `ipprotocol`: `inet`, `inet6`, `inet46`.
* `protocol`: `any`, `tcp`, `udp`, `tcp/udp`, `icmp`, `esp`, `ah`, `gre`, … (default `any`).
* `source` / `destination`: one of `{"any": true}`, `{"address": "<IP, CIDR or alias>"}`,
  `{"network": "lan" | "wanip" | "(self)" …}`; optional `"port": "443" | "1000:2000" | "<alias>"`
  and `"not": true`.
* `position`: `top` (before the interface's existing rules, default) or `bottom`.
* Managed rules carry `[CSFM] ` at the start of their description and are replaced as a block on every
  revision. Edits made to them in the pfSense GUI are overwritten by the next revision.

## port_forward

Inbound NAT (Firewall > NAT > Port Forward). Each entry lets its own traffic through ("Pass"
filter rule association), so no separate firewall rule is needed. Entries are marked `[CSFM]` and
placed at the top (default) or bottom of the firewall's port forwards.

```json
{
  "position": "top",
  "rules": [
    {
      "interface": "wan",
      "protocol": "tcp",
      "source": {"any": true},
      "destination": {"network": "wanip", "port": "443"},
      "target": "192.168.1.10",
      "local_port": "443",
      "descr": "Web server",
      "disabled": false
    }
  ]
}
```

`protocol`: `tcp`, `udp` or `tcp/udp`. `destination.port` (the external port) is required; it and
`local_port` take a port, a range (`8000:8100`) or a port alias. `target` is an IP address or a host
alias. `source` and `destination` take the same forms as in firewall rules.

## notifications

Turns pfSense's own email notifications (System > Advanced > Notifications) on or off:
`{"smtp": false}`. The firewall's SMTP server and addresses are left alone. Unassigning restores the
previous setting. A single firewall can also be switched from its page.

## system

```json
{"hostname": "fw-branch12", "domain": "corp.example", "timezone": "America/New_York",
 "timeservers": "0.pool.ntp.org 1.pool.ntp.org", "dnsservers": ["1.1.1.1", "9.9.9.9"],
 "dnsallowoverride": false, "language": "en_US"}
```

All keys are optional. Original values are remembered and restored when the policy is removed or a
key is dropped from it.

## packages

```json
{"install": ["pfSense-pkg-Status_Traffic_Totals"], "remove": ["pfSense-pkg-nmap"]}
```

Requires *Packages* to be allowed on the firewall in addition to *Policies*. Removing the policy does
not uninstall anything. The ComSense package itself can never be removed this way.

## config_set

For settings without a dedicated policy type. Paths are pfSense config paths (as used by
`config_get_path()`), values are stored as given.

```json
{
  "items": [
    {"path": "system/maximumstates", "value": "400000"},
    {"path": "system/webgui/loginautocomplete", "delete": true}
  ],
  "reload": ["filter"]
}
```

* `reload`: any of `filter`, `dns`, `unbound`, `dnsmasq`, `ntp`, `hostname`, `routing`, `webgui`.
* Users, groups, authentication servers, certificates, CAs and the ComSense package settings are
  protected and cannot be changed by policy.
* Original values are restored when the policy is removed.
