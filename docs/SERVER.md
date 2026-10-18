# Management server

The server is a single Python process (FastAPI) backed by PostgreSQL, with two listeners:

| Listener | Default | Protocol | Expose to |
| --- | --- | --- | --- |
| Web console | `:8000` | plain HTTP | Your HTTPS reverse proxy only (Caddy, Nginx Proxy Manager, Traefik, a VPN/overlay proxy, a WAF…), published on 443 |
| Agent API | `:10443` | TLS, terminated by the app | The internet, or forwarded through NAT; serves nothing but `/api/agent/v1/*` and `/downloads/*` |

So a deployment needs exactly two inbound ports: **443** for admins and **10443** (or any port you choose)
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

Firewalls use the address in their enrollment code: `https://<CSFM_DOMAIN>:10443` by default (outside
Docker, `CSFM_AGENT_URL`, defaulting to `https://<host of CSFM_PUBLIC_URL>:<CSFM_AGENT_PORT>`).
When firewalls reach the agent port under another name or port, for example a separate proxy host name
or a NAT port forward (router port 9443 to the server's 10443), enter it under **Settings → Agent port →
Address firewalls connect to**, e.g. `fw-mgmt.example.com:9443`. It applies to enrollment codes created
afterwards; firewalls already enrolled keep their address. Agents pin the certificate's key rather than
checking its name, so the address can change without a new certificate.

## Requirements

* Linux host (Debian 12, Ubuntu 22.04/24.04 or any distribution with Docker), 1 vCPU and 1 GB RAM
  covers hundreds of firewalls at the default 60 s check-in interval.
* A DNS name. Inbound TCP 443 for admins (plus 80 if Caddy obtains the certificate) and TCP 10443 for firewalls.
* PostgreSQL 13+ (bundled in both install methods).

## Choose a deployment

Pick one of two options. Both run the same app; they differ only in what serves the web console.

| | Option 1: bundled Caddy | Option 2: bring your own proxy |
| --- | --- | --- |
| Web console | Caddy on 80/443 with a free Let's Encrypt certificate | Plain HTTP on `CSFM_WEB_BIND:8000` for your proxy (Nginx Proxy Manager, Traefik, HAProxy, a VPN/overlay proxy, a WAF…) |
| Agent port | 10443, TLS by the app, published directly | Same |
| Ports to forward | 80, 443, 10443 | 10443 (plus whatever your proxy already uses) |
| Docker / Portainer | `deploy/docker-compose.caddy.yml` | `deploy/docker-compose.byo-proxy.yml` |
| Debian/Ubuntu, no Docker | `install-debian.sh <domain> [email]` | `install-debian.sh --byo-proxy[=BIND] <domain>` |

### With Docker Compose

```sh
cd deploy
cp .env.example .env
echo CSFM_SECRET_KEY=$(openssl rand -base64 48 | tr -d '\n/+=') >> .env
echo CSFM_BACKUP_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr '+/' '-_') >> .env
$EDITOR .env          # set CSFM_DOMAIN and POSTGRES_PASSWORD; remove the empty key lines

docker compose -f docker-compose.caddy.yml up -d        # option 1
docker compose -f docker-compose.byo-proxy.yml up -d    # option 2
docker logs comsense-app 2>&1 | grep -A1 'username:'    # first admin's one-time password
```

### With Portainer

*Stacks > Add stack > Repository*, this repository, compose path `deploy/docker-compose.caddy.yml` or
`deploy/docker-compose.byo-proxy.yml`, and add the variables from `.env.example` as stack environment
variables. Portainer builds the image from `server/`. The first admin's password is in the
`comsense-app` container log.

### Debian/Ubuntu without Docker

```sh
sudo ./deploy/install-debian.sh comsense.example.com admin@example.com          # option 1
sudo ./deploy/install-debian.sh --byo-proxy=10.0.0.5 comsense.example.com        # option 2
journalctl -u comsense | grep -A1 'username:'                                    # one-time password
```

The script installs PostgreSQL and Python (and Caddy for option 1) from the distribution, creates the
database with a random password, writes `/etc/comsense/comsense.env` with fresh keys and installs the
sandboxed systemd unit `comsense.service`. With `--byo-proxy` the console listens on the given address
(default 127.0.0.1) port 8000. Re-running it upgrades the code and keeps data and keys.

### Setting up your own proxy (option 2)

Point an HTTPS proxy host for `CSFM_DOMAIN` at `http://<CSFM_WEB_BIND>:8000` (no WebSockets needed). Then lock it down as you see fit; firewalls never use it.
Bind the console to an address only the proxy can reach (127.0.0.1 when the proxy is on the same host,
otherwise a LAN or VPN address). If anything other than the proxy can reach that port, set
`CSFM_FORWARDED_ALLOW_IPS` to the proxy's address.

Do **not** route the agent port through the proxy: forward it straight to the server, so the app's
pinned certificate reaches the firewalls and their real addresses are seen. If `CSFM_DOMAIN` points at
the proxy or a CDN, give the agent port its own DNS name and enter it under **Settings → Agent port**.

If the agent port has to go through a proxy or load balancer anyway, use TCP pass-through, never TLS
termination, so the pinned certificate still reaches the firewalls. To keep the firewalls' real
addresses, have it send a standard PROXY protocol header (v1 or v2) and list its addresses under
**Settings → Addresses → Trusted proxy addresses**. For example: HAProxy `send-proxy-v2`; nginx `stream`
with `proxy_protocol on`; Traefik TCP with `proxyProtocol`; most cloud load balancers have a PROXY
protocol option, as do overlay/VPN proxies with a TCP mode. The agent port accepts the header only
from those addresses; a header from anywhere else closes the connection, and connections without a
header (direct port forwards) keep working as before.

## First sign-in

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
Lost the admin password? `python -m app.cli create-user admin` (in the container:
`docker exec -it comsense-app python -m app.cli create-user admin`) sets a new one-time password.

### Setup wizard

After the new password is set, admins land in a three-step setup wizard (it also opens from the
dashboard while it is unfinished and no firewall is enrolled, and again from **Settings → Run the setup
wizard again**):

1. **Addresses**: the web console address used in email links, the address firewalls connect to, and
   trusted pass-through proxies. Empty fields keep the defaults from the environment.
2. **Email**: the SMTP server, with a test email. Can be skipped.
3. **First firewall**: the agent package (a one-line install command for the firewall shell, or a
   download) and a single-use enrollment code, optionally for a new customer.

Everything is saved to the database and can be changed later on the Settings page.

Data lives in the volumes `comsense-db` (PostgreSQL) and `comsense-data` (encrypted backups, agent
certificate, `downloads`), plus `caddy-data` (certificates) for option 1.

## Customers

Each client is a **customer** (*Customers* in the menu) with contact name, email, phone and notes. A customer
can have any number of firewalls:

* On a customer's page, *Create enrollment key* makes a key bound to that customer; every firewall that
  enrolls with it is filed under the customer automatically. Use one key for a whole rollout, or one per site.
* A firewall can be moved to another customer from its own page (*Settings > Customer*).
* The customer page shows its firewalls (status, version, last check-in, last backup, updates), open
  alerts and enrollment keys. The customer list shows online/offline/awaiting-approval counts and open
  alerts per customer, and links to firewalls not yet assigned to any customer.
* Alerts, the dashboard and alert emails name the customer next to each firewall.

## Settings page, email and alerts

Day-to-day settings are edited by admins under **Settings** in the console and stored in the database,
so the container only needs its start-up variables (below).

* **Outgoing email (SMTP)**: server, port, STARTTLS / SSL, username, password and From address, with
  a *Send test email* button. The SMTP password is stored encrypted with a key derived from
  `CSFM_SECRET_KEY`; if that key changes, enter the password again.
* **Alert emails**: on/off, warnings and critical or critical only, whether to email when an alert
  clears, and extra recipients such as a NOC mailbox. Users opt in with *Email me firewall alerts* on
  their Account page (admins can set it on Settings > Users). New alerts are sent once a minute as one
  summary email per recipient; each alert is emailed once when it opens and once when it clears.
  Alerts that existed before alert email was turned on are not sent. If the mail server is
  unreachable, pending alerts are retried on the next pass.
* **Password reset by email**: with email set up, the sign-in page offers *Forgot password?*.
  Users enter their username or email; if the account has an email address it receives a link that
  works once and expires after an hour. The page answers the same way whether or not the account
  exists. Admins can also send a reset link from Settings > Users. Links point at `CSFM_PUBLIC_URL`.

## Configuration

All settings are environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CSFM_DATABASE_URL` | local PostgreSQL | SQLAlchemy URL |
| `CSFM_SECRET_KEY` | *(required)* | Signs session cookies (32+ characters) |
| `CSFM_BACKUP_ENCRYPTION_KEY` | *(required)* | Fernet key encrypting stored backups. **Back it up**: losing it makes all backups unreadable. |
| `CSFM_ENABLE_FIREWALL_CHANGES` | false | Turns on the "coming soon" features that change firewalls: policies, package installs and upgrades, pfSense upgrades, service restarts, restores and reboots. Off, ComSense only monitors, checks for updates and takes backups. |
| `CSFM_PUBLIC_URL` | | Web console URL |
| `CSFM_WEB_HOST` / `CSFM_WEB_PORT` | `0.0.0.0` / 8000 | Web console listener (plain HTTP, for the proxy) |
| `CSFM_FORWARDED_ALLOW_IPS` | `*` | Proxies trusted for `X-Forwarded-For` on the web listener |
| `CSFM_AGENT_HOST` / `CSFM_AGENT_PORT` | `0.0.0.0` / 10443 | Agent listener (TLS) |
| `CSFM_AGENT_URL` | `https://<public host>:10443` | Default address firewalls use; the Settings page can override it |
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
listeners, and *Settings > Enrollment keys* shows an install command that fetches it from the agent port
and checks its SHA-256 before installing, so it is safe even though `fetch` cannot verify the pinned certificate.
