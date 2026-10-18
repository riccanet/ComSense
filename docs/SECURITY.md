# Security model

## Joining the server

* A firewall can only obtain credentials by presenting an **enrollment key**. Keys are 256-bit random
  values created by an admin, shown once and stored only as a SHA-256 hash. Each can have an
  expiry (7 days by default), a maximum number of uses, a target organization, and can be revoked.
* Keys can require **admin approval**: the firewall is registered but receives no tasks and cannot
  upload backups until an admin approves it.
* Enrollment attempts are rate-limited per source address, and failures are audited.
* On success the firewall receives its own 384-bit **device token**. The server stores only its hash.
  The enrollment key is removed from the firewall's `config.xml` immediately, so it never ends up in
  backups. The token lives in `/var/db/comsense/credentials.json` (root, mode 0600), outside
  `config.xml`, so restoring a config onto other hardware does not clone the identity.
* Tokens rotate automatically every 30 days. Disabling a firewall in the console rejects its token
  immediately; deleting it invalidates the token for good.

## Transport

* The agent only speaks HTTPS (TLS 1.2+), with certificate chain and hostname verification always on,
  no redirects and no other protocols. HTTP URLs are rejected in the settings.
* For private PKI, the CA certificate is configured explicitly; optional public-key pinning makes the
  agent refuse any other server key, even one signed by a trusted CA.
* All connections are outbound from the firewall. Nothing listens on the firewall for management.

## What the server can do to a firewall

The server can only send the fixed task types listed in [PROTOCOL.md](PROTOCOL.md). There is no
"run a command" task. Each action that changes the firewall must also be **allowed locally** in
*Services > ComSense Agent*; the agent refuses anything else regardless of what the server asks, so a
compromised server cannot do more than the firewall owner permitted. By default only backups, policies
and service restarts are allowed; upgrades, package changes, restores and reboots are opt-in.

Policies are validated on both ends; `config_set` cannot touch users, groups, authentication servers,
certificates or the agent's own settings. Changes to rules, DNS and other settings are verified
afterwards and rolled back if the firewall loses contact with the server.

## Data at rest on the server

* Configuration backups contain secrets (password hashes, VPN keys, certificates). They are stored
  encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using `CSFM_BACKUP_ENCRYPTION_KEY`, in files
  readable only by the service user. Downloads and restores require the operator/admin role and are
  audited.
* Passwords are hashed with scrypt. Sessions are signed, HTTP-only, `SameSite=Strict`, `Secure`
  cookies; every form is CSRF-protected; pages are served with a strict Content Security Policy,
  `X-Frame-Options: DENY` and HSTS.

## Recommendations

* Restrict access to the web console (VPN or source-IP allow-list in the proxy) if only the agent
  API needs to be public; the agent only uses `/api/agent/v1/*` and `/downloads/*`.
* Use short-lived, single-organization keys with approval for each rollout, and revoke them after.
* Keep `CSFM_BACKUP_ENCRYPTION_KEY` and `CSFM_SECRET_KEY` in a secrets manager and back them up
  separately from the data.
