# ComSense Firewall Manager

ComSense Firewall Manager (ComSense for short) is self-hosted management and monitoring for fleets of **pfSense CE** and **pfSense Plus** firewalls.

A small agent, installed on each firewall as a native pfSense package, calls out over HTTPS to a
Linux-hosted management server. From the web console you can monitor health, push policies and
settings, run updates and keep encrypted configuration backups. Firewalls never accept inbound
connections for management. A firewall can join the server only after someone enters a one-time
**enrollment key** in the package settings.

```
 ┌────────────────────┐   outbound HTTPS (443)    ┌──────────────────────────────────────┐
 │ pfSense CE / Plus  │ ────────────────────────▶ │ Caddy (TLS, Let's Encrypt)           │
 │                    │   enroll · check-in ·     │   └─ ComSense app (FastAPI)          │
 │ pfSense-pkg-       │   task results · backups  │        ├─ web console (operators)    │
 │ ComSense agent     │ ◀──────────────────────── │        ├─ agent API  /api/agent/v1   │
 │  (PHP, rc service) │   tasks in the response   │        └─ scheduler                  │
 └────────────────────┘                           │  PostgreSQL · encrypted backup store │
                                                  └──────────────────────────────────────┘
```

## Features

| Area | What you get |
| --- | --- |
| **Monitoring** | Online/offline status, CPU, memory, disk, load, pf states, uptime, interfaces, gateways (loss/delay), services, CARP, installed packages; 24 h charts; alerts for down gateways, stopped services, full disks, high memory and firewalls that stop checking in. |
| **Backups** | `config.xml` is uploaded automatically whenever it changes and at least daily, deduplicated by SHA-256, **encrypted at rest**, keeping the last 5 per firewall (configurable) plus any you pin, with download and one-click restore (typed confirmation; reboots the box). |
| **Policies** | Aliases, firewall rules, system settings (DNS, NTP, timezone, hostname/domain), package install/remove, and a restricted generic config setter. Assign to one firewall, an organization or all firewalls. Policies are applied idempotently, report compliance, and removing a policy removes only what it created. Rule, system and config changes are **rolled back automatically if the firewall can no longer reach the server**. |
| **Updates** | Shows available pfSense and package updates; upgrade pfSense, upgrade packages, install/remove packages, restart services, reboot. |
| **Organization** | Organizations (customers/sites), bulk actions, users with admin/operator/viewer roles, full audit log. |
| **Security** | One-time, expiring, revocable enrollment keys (optionally requiring approval); per-device tokens stored hashed and rotated every 30 days; strict TLS on the agent with optional private CA and public-key pinning; every remote action must also be allowed locally on the firewall. See [docs/SECURITY.md](docs/SECURITY.md). |

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

1. **Server** (any Linux host with Docker and a DNS name pointing at it):

   ```sh
   cd deploy
   cp .env.example .env
   docker compose run --rm app python -m app.cli keygen   # paste both values into .env
   $EDITOR .env                                            # set CSFM_DOMAIN, passwords, etc.
   docker compose up -d
   ```

   Or without Docker: `sudo ./deploy/install-debian.sh comsense.example.com you@example.com`.
   Details in [docs/SERVER.md](docs/SERVER.md).

2. **Package**: build `pfSense-pkg-ComSense-<version>.pkg` (`sh agent/build-pkg.sh` on FreeBSD or
   pfSense, or download it from the CI artifacts) and copy it into the server's `downloads` data
   folder so firewalls can fetch it.

3. **Enroll a firewall**: in the console, go to **Enrollment keys** and create a key. On the firewall:

   ```sh
   pkg-static add https://comsense.example.com/downloads/pfSense-pkg-ComSense-0.1.0.pkg
   ```

   Then open **Services > ComSense Agent**, tick *Enable*, enter the server URL and the key, choose
   which remote actions to allow, and save. The firewall enrolls immediately (errors are shown on
   the page) and the key is erased from its configuration. Details in [docs/AGENT.md](docs/AGENT.md).

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
       CSFM_INITIAL_ADMIN_PASSWORD=change-me-please $(python -m app.cli keygen | xargs)
uvicorn app.main:app_factory --factory --reload
```

## Status

Version 0.1.0. The server and the agent's protocol, policy and task logic are covered by automated
tests, including an end-to-end run of the real PHP agent against the real server. The pfSense
integration points (package hooks, GUI pages, pfSense library calls) follow the conventions of
packages in the official pfSense ports tree but should be validated on a lab firewall for each pfSense
version you run before production use.
