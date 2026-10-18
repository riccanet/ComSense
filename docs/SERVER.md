# Management server

The server is a single Python application (FastAPI) backed by PostgreSQL, published through a
TLS-terminating reverse proxy. Firewalls connect to it on **HTTPS port 443** (or whatever port the
proxy listens on). It needs a DNS name with a certificate the firewalls trust; with the provided
Caddy configuration that is a free Let's Encrypt certificate obtained automatically.

## Requirements

* Linux host (Debian 12, Ubuntu 22.04/24.04 or any distribution with Docker), 1 vCPU and 1 GB RAM
  covers hundreds of firewalls at the default 60 s check-in interval.
* A DNS name, with inbound TCP 80 (certificate issuance) and 443 open to the firewalls and admins.
* PostgreSQL 13+ (bundled in both install methods).

## Option A: Docker Compose

```sh
cd deploy
cp .env.example .env
docker compose run --rm app python -m app.cli keygen
```

Copy the two printed lines into `.env`, then set `PFM_DOMAIN`, `ACME_EMAIL`, `POSTGRES_PASSWORD` and
`PFM_INITIAL_ADMIN_PASSWORD`, and start it:

```sh
docker compose up -d
docker compose logs -f app
```

Volumes: `db-data` (PostgreSQL), `app-data` (encrypted backups and the `downloads` folder),
`caddy-data` (certificates).

## Option B: Debian/Ubuntu without Docker

```sh
sudo ./deploy/install-debian.sh pfmanager.example.com admin@example.com
```

The script installs PostgreSQL, Python and Caddy from the distribution, creates the database with a
random password, writes `/etc/pfmanager/pfmanager.env` with fresh keys, installs the systemd unit
`pfmanager.service` (sandboxed, listening on 127.0.0.1:8000) and configures Caddy. It prints the
initial admin password once. Re-running it upgrades the code and keeps data and keys.

## Using your own certificate or reverse proxy

Any proxy works if it terminates TLS, forwards to the app on port 8000 and sets `X-Forwarded-For`.
Allow request bodies of at least `PFM_MAX_BACKUP_BYTES` (32 MiB by default) for backup uploads.
If the certificate is from a private CA, paste that CA into *Server CA certificate* in each
firewall's package settings.

## Configuration

All settings are environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PFM_DATABASE_URL` | local PostgreSQL | SQLAlchemy URL |
| `PFM_SECRET_KEY` | *(required)* | Signs session cookies (32+ characters) |
| `PFM_BACKUP_ENCRYPTION_KEY` | *(required)* | Fernet key encrypting stored backups. **Back it up**: losing it makes all backups unreadable. |
| `PFM_PUBLIC_URL` | | URL shown to admins for enrolling firewalls |
| `PFM_DATA_DIR` | `/var/lib/pfmanager` | Backups (`backups/`) and agent packages (`downloads/`) |
| `PFM_INITIAL_ADMIN_USER` / `_PASSWORD` | `admin` / empty | First admin, created only when there are no users |
| `PFM_CHECKIN_INTERVAL` | 60 | Seconds between agent check-ins (sent to agents) |
| `PFM_OFFLINE_AFTER` | 300 | Seconds without a check-in before a firewall is marked offline |
| `PFM_SCHEDULED_BACKUP_HOURS` | 24 | Queue a backup when the newest is older than this (0 disables) |
| `PFM_BACKUP_RETENTION_COUNT` | 100 | Unpinned backups kept per firewall |
| `PFM_METRICS_RETENTION_DAYS` | 30 | Metric history kept |
| `PFM_MAX_BACKUP_BYTES` | 33554432 | Largest accepted config.xml |
| `PFM_SESSION_MAX_AGE` | 28800 | Web session lifetime in seconds |
| `PFM_SECURE_COOKIES` | true | Set false only for local HTTP development |

Run the app with **one worker** (`--workers 1`, as shipped): the housekeeping scheduler and the
login/enrollment rate limiters live in the process.

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
files are useless without `PFM_BACKUP_ENCRYPTION_KEY`, so store that key separately from them.

## Hosting the agent package

Copy `pfSense-pkg-PfManager-<version>.pkg` into `<PFM_DATA_DIR>/downloads/`. It is then served at
`https://<server>/downloads/<file>` and the *Enrollment keys* page shows the exact install command.
