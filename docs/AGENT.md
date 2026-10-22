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
| `/usr/local/sbin/comsense-watchdogd` | Change watchdog (automatic rollback), started next to the agent loop |
| `/usr/local/www/comsense_status.php` | Status tab: enrollment, last check-in, managed policies, *Check in now* |
| `/etc/inc/priv/comsense.priv.inc` | GUI privilege so access can be delegated |
| `/var/db/comsense/` (0700) | Device credential, state, optional server CA (created at runtime) |
| `/cf/conf/comsense/` (0700) | Known-good copy of `config.xml` while a change is on probation (next to `config.xml`, so it survives a reboot even with RAM disks) |

The service appears under **Status > Services** as `comsense`. Logs go to the system log
(**Status > System Logs > General**, program `comsense`).

## Building the package

The package has no compiled code. **The server builds it itself** on every start from the agent source
it ships with (`app/services/agentpkg.py`) and serves it from its `downloads` folder, so a normal install
needs nothing else: the setup wizard and *Settings > Enrollment keys* show the install command and a
download link. That package is marked `FreeBSD:*`, so the same file installs on pfSense CE and Plus,
on x86-64 (`amd64`) and ARM (`aarch64` Netgate appliances such as the 1100, 2100, 4200 and 6100, and
32-bit `armv7` such as the SG-3100). The agent is PHP and shell only, with nothing CPU-specific.
A package you copy into `downloads` under the same name yourself is kept as it is.
Once installed it is listed under **System > Package Manager > Installed Packages**, where it can be
removed like any other package.

To build it the classic way instead (anywhere `pkg(8)` exists):

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

Copy the install command from the server's *Settings > Enrollment keys* page. It looks like:

```sh
fetch -o /tmp/comsense.pkg --no-verify-peer --no-verify-hostname https://comsense.example.com:10443/downloads/pfSense-pkg-ComSense-0.2.17.pkg \
  && [ "$(sha256 -q /tmp/comsense.pkg)" = "<sha256 shown on the page>" ] \
  && pkg-static add -f /tmp/comsense.pkg
```

`--no-verify-peer --no-verify-hostname` are there because the agent port uses the server's own
certificate (FreeBSD's `fetch` checks the name even with `--no-verify-peer`); the SHA-256 check is what
guarantees you install the genuine package. The agent itself pins the server's key instead.

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
| Enrollment code | Paste the code from the server's *Settings > Enrollment keys* page. It holds the agent address (`https://host:10443`), a one-time key and the server's public key pin. On **Save** the firewall enrolls immediately; a wrong code, address or pin is shown as an error on the page. On success the key is cleared from `config.xml` and replaced by a per-device token in `/var/db/comsense/credentials.json` (mode 0600), which is not part of config backups. Paste a new code at any time to re-enroll. A bare key also works if you fill in the fields below yourself. |
| Server URL | Filled in from the code: the server's **agent** port, e.g. `https://comsense.example.com:10443`. HTTP URLs are rejected. |
| Public key pin | Filled in from the code when the server uses its own certificate. The agent then trusts exactly this key and nothing else. Empty for a publicly trusted certificate. |
| Server CA certificate | Rarely needed: only for an agent-port certificate issued by your private CA. |
| Allowed remote actions | What the server may change: backups, policies, packages, upgrades, service restarts, restore, reboot, and the remote terminal (see [SECURITY.md](SECURITY.md#remote-terminal)). Monitoring is always on. The agent refuses anything not ticked here, whatever the server asks. |

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

Between cycles the agent waits on the server (`GET /wait`, a long poll of up to 55 s at a time), so
*Check now* in the console reaches a connected firewall within a few seconds. The firewall still only
makes outgoing connections. If the server cannot be reached the agent simply sleeps until the next
check-in.

### Updating the agent from the console

When the server has a newer agent package than a firewall runs, the firewall's page shows
*Update agent to x.y.z* (and the firewall list offers it as a bulk action). The agent downloads the
package over its pinned, authenticated connection, checks its SHA-256, installs it with
`pkg-static add -f` and restarts itself; the task turns green when the new version checks in. It needs
the **Upgrades** permission on the firewall (Services > ComSense Agent). Agents older than 0.1.9 do not know
this task: install 0.1.9 once by hand.

Each cycle runs in a new PHP process so it always sees the current configuration, under a lock so a
manual *Check in now* cannot overlap a scheduled one.

## Surviving pfSense upgrades

pfSense reinstalls packages from Netgate's repository after an upgrade, and this package is not in it,
so an upgrade would leave the firewall without its agent. The agent therefore keeps, outside its
package (pkg never removes them):

* `/var/db/comsense/recovery/pfSense-pkg-ComSense-<version>.pkg`, a copy of itself, fetched over its
  pinned connection from the server;
* `/var/db/comsense/recovery/recover.sh`, a boot script, registered as a pfSense *shellcmd*
  (`system/shellcmd` in config.xml, which upgrades keep).

At boot the script waits for pfSense to finish reinstalling its own packages and, if the agent is
missing, installs the copy. Credentials and settings survive the upgrade, so it carries on as the same
firewall and reports the upgrade's result. Removing the package on purpose (Package Manager, or
`pkg delete` outside an upgrade) removes the shellcmd and the copy, so it does not come back.
Requires agent 0.2.4 or later before the upgrade.

## Automatic rollback (failback)

A change made from ComSense must not leave a firewall that ComSense can no longer reach. Every task
that changes the configuration (applying or removing a policy, restoring a backup) runs under a
**change guard**, the same idea as "commit confirmed" on routers:

1. **Before the change** the agent copies `config.xml` and its own policy records to
   `/cf/conf/comsense/`.
2. **Right after the change** it checks that the server still answers. If not, it puts the copy back
   at once, reapplies it (`/etc/rc.reload_all`), and the task fails with *Rolled back*. Other changes
   queued in the same check-in are not run.
3. **The change then stays on probation** for 5 minutes (15 minutes for a restore, which reboots).
   A check-in at least a minute after the change confirms it. Otherwise the watchdog
   (`comsense-watchdogd`, its own process, checking every 30 seconds) tests the connection when the
   window ends: if the server answers, the change is kept; if not, the copy is put back and reloaded,
   or for a restore, put back and the firewall rebooted.
4. **The rollback is reported** at the next check-in. The console raises a critical alert, marks the
   tasks as rolled back, and stops sending that policy revision to that firewall, so a bad change
   cannot loop. It goes out again when the policy gets a new revision, or after *Clear and allow
   again* on the firewall's page.

Any HTTP answer from the server counts as reachable; only connection failures (DNS, routing,
filtering, proxy, TLS) cause a rollback. Changes made within one probation window share a single
copy, so a rollback returns to the configuration from before the first of them. A restore is
refused if the backup does not contain the ComSense agent settings, because the firewall could not
reconnect afterwards. System and package upgrades cannot be undone this way.

On the firewall, **Services > ComSense Agent > Status** shows a change on probation, with *Keep the
change* and *Roll back now*, and the last automatic rollback.

## Command line

```sh
php /usr/local/pkg/comsense/agent.php status     # enrollment state, last check-in, last error
php /usr/local/pkg/comsense/agent.php run -v     # one cycle, verbose
php /usr/local/pkg/comsense/agent.php backup     # upload config.xml now
php /usr/local/pkg/comsense/agent.php unenroll   # forget the device token
php /usr/local/pkg/comsense/agent.php wait 60    # wait up to 60 s for work from the server
php /usr/local/pkg/comsense/agent.php terminal ID  # run an approved terminal session (started by the daemon)
php /usr/local/pkg/comsense/agent.php watchdog   # roll back a change whose probation ended without contact
php /usr/local/pkg/comsense/agent.php confirm    # keep the change on probation
php /usr/local/pkg/comsense/agent.php rollback   # undo the change on probation now
```
