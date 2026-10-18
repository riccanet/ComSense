# Management server

The server is a single Python process (FastAPI) backed by PostgreSQL, with two listeners:

| Listener | Default | Protocol | Expose to |
| --- | --- | --- | --- |
| Web console | `:8000` | plain HTTP | Your HTTPS reverse proxy only (Caddy, Nginx Proxy Manager, NetBird, a WAF…), published on 443 |
| Agent API | `:8443` | TLS, terminated by the app | The internet, or forwarded through NAT; serves nothing but `/api/agent/v1/*` and `/downloads/*` |

So a deployment needs exactly two inbound ports: **443** for admins and **8443** (or any port you choose)
for firewalls. Because agents never touch the web console, you can restrict 443 as tightly as you like
(source allow-list, geo-blocking, CrowdSec, SSO in front, VPN only) without affecting the fleet.

### Agent TLS

By default the server issues its own certificate for the agent port, stored in
`<CSFM_DATA_DIR>/tls/`. It is valid for about two years and renewed automatically, keeping the same key,
when the server starts within 30 days of expiry. Every agent pins that key: the pin
travels inside the enrollment code, and a connection to any other key is refused before anything is sent.
No public DNS validation or Let's Encrypt is needed for the agent port.

To use a certificate of your own instead (for example one from your PKI), set `CSFM_AGENT_TLS_CERT` and
`CSFM_AGENT_TLS_KEY`. Agents then verify it against public CAs (or the CA pasted in their settings) and
enrollment codes carry no pin. Avoid this with Let's Encrypt certificates whose key changes on renewal.

### The agent address

Firewalls use `CSFM_AGENT_URL`, which defaults to `https://<host of CSFM_PUBLIC_URL>:<CSFM_AGENT_PORT>`.
Set it when the outside port or name differs because of NAT, e.g. `CSFM_AGENT_URL=https://fw-mgmt.example.com:9443`
with the router forwarding 9443 to the server's 8443. Names and IPs in this URL go into the
self-issued certificate; add more with `CSFM_AGENT_TLS_NAMES`.

## Requirements

* Linux host (Debian 12, Ubuntu 22.04/24.04 or any distribution with Docker), 1 vCPU and 1 GB RAM
  covers hundreds of firewalls at the default 60 s check-in interval.
* A DNS name. Inbound TCP 443 for admins (plus 80 if Caddy obtains the certificate) and TCP 8443 for firewalls.
* PostgreSQL 13+ (bundled in both install methods).

## Option A: Docker Compose

```sh
cd deploy
cp .env.example .env
docker compose run --rm app python -m app.cli keygen
```

Copy the two printed lines into `.env`, then set `CSFM_DOMAIN`, `ACME_EMAIL` and `POSTGRES_PASSWORD`,
and start it:

```sh
docker compose up -d
docker compose logs app | grep -A1 'username:'   # the first admin's one-time password
```

### First sign-in

On its first start the server creates the admin account (`CSFM_INITIAL_ADMIN_USER`, default `admin`)
with a random one-time password unique to that install, and writes it to the log once, in a banner:

```
================================================================
  ComSense first start: initial administrator created
    username: admin
    password: <one-time password shown here>
  This one-time password must be changed at first sign-in.
================================================================
```

Signing in with it leads straight to *Choose a new password*; nothing else is reachable until it is
changed. Passwords that admins set for other users, or reset, are one-time in the same way.
Lost the admin password? `python -m app.cli create-user admin` sets a new one-time password.

Volumes: `db-data` (PostgreSQL), `app-data` (encrypted backups and the `downloads` folder),
`caddy-data` (certificates).

## Option B: Debian/Ubuntu without Docker

```sh
sudo ./deploy/install-debian.sh comsense.example.com admin@example.com
```

The script installs PostgreSQL, Python and Caddy from the distribution, creates the database with a
random password, writes `/etc/comsense/comsense.env` with fresh keys, installs the systemd unit
`comsense.service` (sandboxed, listening on 127.0.0.1:8000) and configures Caddy. It prints the
initial admin password once. Re-running it upgrades the code and keeps data and keys.

## Using your own certificate or reverse proxy

Any proxy works for the web console if it terminates TLS, forwards to the app's web port (8000) and sets
`X-Forwarded-For`. Set `CSFM_FORWARDED_ALLOW_IPS` to the proxy's address if anything other than the proxy
can reach port 8000. The agent port is not proxied: forward it straight to the app, so agents' real
addresses are seen and per-address lockouts work.

A Portainer stack for running behind an existing proxy is in `deploy/portainer-stack.yml`.

## Configuration

All settings are environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CSFM_DATABASE_URL` | local PostgreSQL | SQLAlchemy URL |
| `CSFM_SECRET_KEY` | *(required)* | Signs session cookies (32+ characters) |
| `CSFM_BACKUP_ENCRYPTION_KEY` | *(required)* | Fernet key encrypting stored backups. **Back it up**: losing it makes all backups unreadable. |
| `CSFM_PUBLIC_URL` | | Web console URL |
| `CSFM_WEB_HOST` / `CSFM_WEB_PORT` | `0.0.0.0` / 8000 | Web console listener (plain HTTP, for the proxy) |
| `CSFM_FORWARDED_ALLOW_IPS` | `*` | Proxies trusted for `X-Forwarded-For` on the web listener |
| `CSFM_AGENT_HOST` / `CSFM_AGENT_PORT` | `0.0.0.0` / 8443 | Agent listener (TLS) |
| `CSFM_AGENT_URL` | `https://<public host>:8443` | Address firewalls use, after NAT; put into enrollment codes |
| `CSFM_AGENT_TLS_CERT` / `_KEY` | self-issued | Use your own certificate for the agent listener |
| `CSFM_AGENT_TLS_NAMES` | | Extra DNS names / IPs for the self-issued certificate, comma separated |
| `CSFM_DATA_DIR` | `/var/lib/comsense` | Backups (`backups/`) and agent packages (`downloads/`) |
| `CSFM_INITIAL_ADMIN_USER` | `admin` | Username of the first admin, created on first start with a random one-time password |
| `CSFM_CHECKIN_INTERVAL` | 60 | Seconds between agent check-ins (sent to agents) |
| `CSFM_OFFLINE_AFTER` | 300 | Seconds without a check-in before a firewall is marked offline |
| `CSFM_SCHEDULED_BACKUP_HOURS` | 24 | Queue a backup when the newest is older than this (0 disables) |
| `CSFM_BACKUP_RETENTION_COUNT` | 5 | Most recent distinct backups kept per firewall; pinned backups are kept in addition |
| `CSFM_TASK_RETENTION_DAYS` | 90 | Finished tasks older than this are deleted (0 keeps them forever) |
| `CSFM_METRICS_RETENTION_DAYS` | 30 | Metric history kept |
| `CSFM_MAX_BACKUP_BYTES` | 33554432 | Largest accepted config.xml |
| `CSFM_SESSION_MAX_AGE` | 28800 | Web session lifetime in seconds |
| `CSFM_SECURE_COOKIES` | true | Set false only for local HTTP development |

Start it with `python -m app.serve` (as the provided Dockerfile and systemd unit do). Run **one process**:
the housekeeping scheduler and the login, enrollment and failed-token limiters live in it.

## Administration

```sh
python -m app.cli keygen                          # new secret and backup keys
python -m app.cli create-user alice --role operator   # create a user or reset a password
```

(With Docker: `docker compose exec app python -m app.cli ...`.)

Roles: **viewer** sees everything; **operator** also runs tasks, edits policies and downloads backups;
**admin** also manages users, enrollment keys, approvals, restores and deletions.

## Backing up the server

Back up the PostgreSQL database (`pg_dump`), the data directory and the environment file. The backup
files are useless without `CSFM_BACKUP_ENCRYPTION_KEY`, so store that key separately from them.

## Hosting the agent package

Copy `pfSense-pkg-ComSense-<version>.pkg` into `<CSFM_DATA_DIR>/downloads/`. It is then served on both
listeners, and the *Enrollment keys* page shows an install command that fetches it from the agent port
and checks its SHA-256 before installing, so it is safe even though `fetch` cannot verify the pinned certificate.
