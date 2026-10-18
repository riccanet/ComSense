# Security model

## Joining the server

* A firewall can only obtain credentials by presenting an **enrollment key**. Keys are 256-bit random
  values created by an admin, shown once and stored only as a SHA-256 hash. Each can have an
  expiry (7 days by default), a maximum number of uses, a target customer, and can be revoked.
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

* Agents talk to a **dedicated listener** on its own port (10443 by default). It serves only the agent API
  and package downloads; the web console is a different listener that should be reachable only through
  your reverse proxy. Admins can therefore lock the console down completely (allow-lists, WAF, SSO,
  VPN) while the fleet keeps working, and the internet-facing surface is limited to token-authenticated
  agent endpoints.
* The agent only speaks HTTPS (TLS 1.2+), with no redirects and no other protocols; HTTP URLs are
  rejected in the settings.
* By default the server issues its own certificate for the agent port and every agent **pins its
  public key**, delivered inside the enrollment code. A connection to any other key is refused before
  anything is sent, so neither a rogue certificate authority nor a mis-issued certificate can
  intercept agents. The key is kept across renewals, so the pin never changes.
* With an operator-supplied certificate, agents verify the chain and hostname instead.
* Bad device tokens are counted per source address; after 20 in 10 minutes the address is refused.
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

## Email and password resets

* Reset links carry a 256-bit random token stored only as a hash, expire after one hour, work once,
  and revoke any earlier link for the same user. Setting a new password ends that user's existing sessions.
* *Forgot password?* gives the same answer for unknown accounts and accounts without email, sends the
  email after the response, and is rate-limited per address.
* The SMTP password is encrypted at rest with a key derived from `CSFM_SECRET_KEY`.

## Recommendations

* Restrict the web console (port 443) to admins: source allow-list, VPN, or SSO in your proxy.
  Firewalls never need it. Only the agent port has to be reachable from the internet.
* Use short-lived, single-customer keys with approval for each rollout, and revoke them after.
* Keep `CSFM_BACKUP_ENCRYPTION_KEY` and `CSFM_SECRET_KEY` in a secrets manager and back them up
  separately from the data.
