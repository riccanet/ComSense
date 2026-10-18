<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="server/app/static/brand/logo-dark.svg">
    <img alt="ComSense Firewall Manager" src="server/app/static/brand/logo-light.svg" width="320">
  </picture>
</p>

# ComSense Firewall Manager

ComSense Firewall Manager (ComSense for short) is self-hosted management and monitoring for fleets of **pfSense CE** and **pfSense Plus** firewalls.

A small agent, installed on each firewall as a native pfSense package, calls out over TLS to a
Linux-hosted management server. From the web console you can monitor health, push policies and
settings, run updates and keep encrypted configuration backups. Firewalls never accept inbound
connections for management. A firewall can join the server only after someone pastes a one-time
**enrollment code** into the package settings.

The server has two separate listeners, so it needs only two ports forwarded through NAT:

| Port | Serves | Who reaches it |
| --- | --- | --- |
| **443** (via your reverse proxy) | Web console | Admins. Put it behind whatever protection you use: allow-list, WAF, SSO proxy, VPN. |
| **10443** (configurable) | Agent API only, TLS terminated by the app | Firewalls. Each agent pins the server's key, so no public certificate is needed. |

```
                                                  ┌──────────────────────────────────────┐
 ┌────────────────────┐  TLS :10443, pinned key   │ ComSense app                         │
 │ pfSense CE / Plus  │ ────────────────────────▶ │   ├─ agent listener :10443 (own TLS) │
 │                    │   enroll · check-in ·     │   │    agent API only                │
 │ pfSense-pkg-       │   task results · backups  │   ├─ web console :8000 (HTTP) ◀──┐   │
 │ ComSense agent     │ ◀──────────────────────── │   └─ scheduler                   │   │
 │  (PHP, rc service) │   tasks in the response   │  PostgreSQL · encrypted backups  │   │
 └────────────────────┘                           └──────────────────────────────────┼───┘
                                      admins ──▶ HTTPS :443 reverse proxy (Caddy, ─┘
                                                 NPM, Traefik, WAF, allow-list…)
```

## Features

> Features that change firewalls (policies, package and pfSense upgrades, service restarts, restores and
> reboots) are marked **Coming soon** in the console and are switched off unless
> `CSFM_ENABLE_FIREWALL_CHANGES=true`. Monitoring, alerts, update checks and backups work today.

| Area | What you get |
| --- | --- |
| **Monitoring** | Online/offline status, CPU, memory, disk, load, pf states, uptime, interfaces, gateways (loss/delay), services, CARP, installed packages; 24 h charts; alerts for down gateways, stopped services, full disks, high memory and firewalls that stop checking in. |
| **Backups** | `config.xml` is uploaded automatically whenever it changes and at least daily, deduplicated by SHA-256, **encrypted at rest**, keeping the last 5 per firewall (configurable) plus any you pin, with download and one-click restore (typed confirmation; reboots the box). |
| **Policies** | Aliases, firewall rules, system settings (DNS, NTP, timezone, hostname/domain), package install/remove, and a restricted generic config setter. Assign to one firewall, a customer or all firewalls. Policies are applied idempotently, report compliance, and removing a policy removes only what it created. Every change is **rolled back automatically if the firewall can no longer reach the server**, right away or when a 5-minute probation ends, even across a reboot. |
| **Updates** | Shows available pfSense and package updates; upgrade pfSense, upgrade packages, install/remove packages, restart services, reboot. |
| **Email** | SMTP settings on the console's Settings page (stored in the database, password encrypted). Alert emails as per-minute summaries to opted-in users and extra addresses, by severity, with optional "cleared" notices. Self-service password reset links. |
| **Customers** | Group each client's firewalls under a customer with contact details; a customer page shows its firewalls, open alerts, last backups and enrollment keys, and keys made for a customer drop new firewalls straight into it. Bulk actions, users with admin/operator/viewer roles, full audit log. Light, dark and automatic (follow the OS) themes. |
| **Security** | Two-factor sign-in with an authenticator app (TOTP, with recovery codes) or email codes, optional or required for admins or everyone. Separate agent port serving only the agent API, with the server's own certificate pinned by every agent; failed-token lockout per address. One-time, expiring, revocable enrollment keys (optionally requiring approval); per-device tokens stored hashed and rotated every 30 days; strict TLS on the agent with optional private CA and public-key pinning; every remote action must also be allowed locally on the firewall. See [docs/SECURITY.md](docs/SECURITY.md). |

## Repository layout

```
server/                      Management server (Python 3.11+, FastAPI, SQLAlchemy, PostgreSQL)
  app/api/agent.py           HTTPS API used by the agents
  app/web/                   Web console (server-rendered, no external assets)
  app/services/              Policies, tasks, backups, alerts
  tests/                     pytest suite
agent/
  pfSense-pkg-ComSense/     FreeBSD port for the pfSense package (Makefile, plist, files/)
  build-pkg.sh               Builds the .pkg on FreeBSD or on a pfSense box without a ports tree
  tests/                     End-to-end test: the real agent code against a real server over TLS
deploy/                      docker-compose + Caddy, or a bare-metal Debian/Ubuntu installer
docs/                        Server, agent, protocol, policy and security documentation
```

## Quick start

1. **Server**: choose **bundled Caddy** (it gets the console a Let's Encrypt certificate) or
   **bring your own proxy** (any reverse proxy: Nginx Proxy Manager, Traefik, HAProxy, a WAF…). With Docker:

   ```sh
   cd deploy && cp .env.example .env     # set CSFM_DOMAIN, POSTGRES_PASSWORD and the two keys
   docker compose -f docker-compose.caddy.yml up -d       # option 1
   docker compose -f docker-compose.byo-proxy.yml up -d   # option 2
   docker logs comsense-app 2>&1 | grep -A1 'username:'   # first admin's one-time password
   ```

   Both work as Portainer stacks too. Without Docker:
   `sudo ./deploy/install-debian.sh [--byo-proxy] comsense.example.com`.
   Details in [docs/SERVER.md](docs/SERVER.md).

2. **Sign in and run the setup wizard**: the first admin's one-time password is in the server log. After
   you choose a new one, the wizard asks for the console and agent addresses and the SMTP server, then
   gets your first firewall connected. The server builds the agent package itself, so there is nothing
   to build or copy.

3. **Enroll more firewalls**: go to **Settings > Enrollment keys** and create a key. The page shows an
   install command (it downloads the package from the agent port and checks its SHA-256) and an
   **enrollment code**. On the firewall, run the install command, then open
   **Services > ComSense Agent**, tick *Enable*, paste the code, choose which remote actions to allow,
   and save. The firewall enrolls immediately (errors are shown on the page) and the key is erased
   from its configuration. Details in [docs/AGENT.md](docs/AGENT.md).

## Development

```sh
pip install -r server/requirements-dev.txt
python -m pytest server/tests          # server unit/integration tests
python -m pytest agent/tests           # PHP agent end-to-end over TLS (needs php-cli with curl, openssl)
```

Run the server locally against SQLite:

```sh
cd server
export CSFM_DATABASE_URL=sqlite:///./dev.db CSFM_DATA_DIR=./data CSFM_SECURE_COOKIES=false \
       $(python -m app.cli keygen | xargs)   # the admin's one-time password is printed in the log
python -m app.serve        # web console on :8000, agent listener on :10443
```

## Status

Version 0.2.1. The server and the agent's protocol, policy and task logic are covered by automated
tests, including an end-to-end run of the real PHP agent against the real server. The pfSense
integration points (package hooks, GUI pages, pfSense library calls) follow the conventions of
packages in the official pfSense ports tree but should be validated on a lab firewall for each pfSense
version you run before production use.
