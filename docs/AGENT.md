# pfSense agent package

`pfSense-pkg-ComSense` installs a small agent written in PHP (the language pfSense itself is built
on) so it can use pfSense's own configuration and status functions. It works on pfSense CE 2.7+ and
pfSense Plus 23.01+.

## What it installs

| Path | Purpose |
| --- | --- |
| `/usr/local/pkg/comsense.xml`, `comsense.inc` | Package definition (Services > ComSense Agent) and hooks |
| `/usr/local/pkg/comsense/agent.php`, `lib/*.inc` | Agent: HTTPS client, collectors, task runner, policy engine |
| `/usr/local/sbin/comsense-agentd` | Check-in loop, run by `/usr/local/etc/rc.d/comsense.sh` under daemon(8) |
| `/usr/local/www/comsense_status.php` | Status tab: enrollment, last check-in, managed policies, *Check in now* |
| `/etc/inc/priv/comsense.priv.inc` | GUI privilege so access can be delegated |
| `/var/db/comsense/` (0700) | Device credential, state, optional server CA (created at runtime) |

The service appears under **Status > Services** as `comsense`. Logs go to the system log
(**Status > System Logs > General**, program `comsense`).

## Building the package

The package has no compiled code, so it builds quickly anywhere `pkg(8)` exists.

* **On FreeBSD or directly on a pfSense box:**
  ```sh
  sh agent/build-pkg.sh                     # ABI of the build host, e.g. FreeBSD:14:*
  sh agent/build-pkg.sh -a 'FreeBSD:15:*'    # e.g. for pfSense Plus 24.x / 25.x
  ```
  Output: `agent/dist/pfSense-pkg-ComSense-<version>.pkg`. Build for the FreeBSD major version of
  the target: pfSense CE 2.7.x/2.8.x are FreeBSD 14; recent pfSense Plus releases are FreeBSD 15.
* **In CI:** the `package` job in `.github/workflows/ci.yml` builds it in a FreeBSD VM and uploads it
  as an artifact.
* **With a ports tree / poudriere:** copy `agent/pfSense-pkg-ComSense` to `sysutils/` and build it
  like any other pfSense package.

## Installing on a firewall

From **Diagnostics > Command Prompt** or an SSH shell:

```sh
pkg-static add https://comsense.example.com/downloads/pfSense-pkg-ComSense-0.1.0.pkg
```

If pkg refuses because of an OS version mismatch, the package was built for another FreeBSD
major version: rebuild it with the right `-a` value rather than forcing it.

The package registers itself with pfSense on install (menu entry, service, privileges). Removing it
with `pkg-static delete pfSense-pkg-ComSense` stops and unregisters the agent. `/var/db/comsense`
is kept so a reinstall keeps its identity; delete that directory to reset completely.

> pfSense does not list third-party packages in **System > Package Manager**, and a pfSense upgrade
> can remove packages that are not in the official repository. After a major pfSense upgrade,
> confirm the agent is still installed (the server marks the firewall offline if not).

## Settings (Services > ComSense Agent)

| Setting | |
| --- | --- |
| Enable | Runs the agent service. |
| Server URL | `https://` URL of the server, with `:port` if not 443. HTTP URLs are rejected. |
| Enrollment key | One-time key from the server. On **Save** the firewall enrolls immediately; a wrong URL, certificate or key is shown as an error on the page. On success the key is cleared from `config.xml` and replaced by a per-device token in `/var/db/comsense/credentials.json` (mode 0600), which is not part of config backups. Enter a new key at any time to re-enroll. |
| Server CA certificate | Only for servers whose certificate is not publicly trusted. |
| Public key pin | Optional base64 SHA-256 of the server public key(s). Get it with: `openssl s_client -connect host:443 </dev/null 2>/dev/null \| openssl x509 -pubkey -noout \| openssl pkey -pubin -outform der \| openssl dgst -sha256 -binary \| base64` |
| Allowed remote actions | What the server may change: backups, policies, packages, upgrades, service restarts, restore, reboot. Monitoring is always on. The agent refuses anything not ticked here, whatever the server asks. |

The agent also uses the proxy configured in **System > Advanced > Miscellaneous**, if any.

## How it works

Every check-in interval (60 s by default, set by the server) the agent:

1. Reports results of tasks that could not be delivered earlier, and of a system upgrade that has
   completed (or rebooted the box).
2. Sends a report: system info, metrics, interfaces, gateways, services, CARP, packages, update
   availability (refreshed every 6 h), the SHA-256 of `config.xml` and the policies it has applied.
3. Receives the device status and up to 10 tasks. If the server says its stored config is out of
   date, uploads `config.xml`.
4. Runs the tasks in a safe order (rules are removed before aliases, aliases created before rules)
   and reports each result.

Each cycle runs in a new PHP process so it always sees the current configuration, under a lock so a
manual *Check in now* cannot overlap a scheduled one.

## Command line

```sh
php /usr/local/pkg/comsense/agent.php status     # enrollment state, last check-in, last error
php /usr/local/pkg/comsense/agent.php run -v     # one cycle, verbose
php /usr/local/pkg/comsense/agent.php backup     # upload config.xml now
php /usr/local/pkg/comsense/agent.php unenroll   # forget the device token
```
