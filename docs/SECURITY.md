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
* A PROXY protocol header on the agent port (for a pass-through proxy that forwards real client
  addresses) is honoured only from the trusted proxy networks set on the Settings page; from any other
  address the connection is closed, so client addresses used for rate limiting and audit cannot be spoofed.
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
and service restarts are allowed; upgrades, package changes, restores, reboots and the remote terminal
are opt-in.

### Single sign-on (SAML)

Settings > Single sign-on adds SAML 2.0 identity providers: Google Workspace, Microsoft Entra ID,
Cisco Duo or any other. ComSense is the service provider:

* Only sign-ins started from the ComSense sign-in page are accepted (no IdP-initiated sign-in). Each
  request id is used once, within 10 minutes, and is tied to the browser that started it by a
  short-lived cookie.
* The response or assertion must be signed with the provider's certificate (checked with signxml;
  only the signed part is used). Issuer, status, audience (the Entity ID), recipient (the ACS URL),
  validity times (3 minutes of clock skew) and single use of each assertion are checked. Encrypted
  assertions are not supported.
* People are matched to ComSense users by email address. Unless the provider is set to create users
  (with a chosen role), only existing users can sign in. Roles stay managed in ComSense.
* The provider applies its own MFA (Entra Conditional Access, Duo, Google 2-Step Verification), so an
  SSO sign-in counts as two-factor for "require two-factor sign-in". Remote terminal sessions still
  need an authenticator app in ComSense.
* Sign-ins and failures are in the audit log. Passwords keep working alongside SSO.

### Remote terminal

A root shell on the firewall from the console, for troubleshooting. Because it is unrestricted, it is
guarded on both sides:

* **Off on every firewall** until someone with access to that firewall ticks *Remote terminal* in
  *Services > ComSense Agent*. The server cannot turn it on.
* **Admins only, and every session is approved with the admin's authenticator app (TOTP).** Admins
  without an authenticator app cannot open terminals at all; emailed codes and recovery codes are not
  accepted. A code works once, and 5 wrong codes lock terminal approval for 15 minutes.
* The approval is bound to the admin's browser session and must be used within 2 minutes; a session
  can be joined once and cannot be reattached after a disconnect.
* The session starts in pfSense's console menu, as on the console or over SSH: option 8 opens a
  root shell, option 0 ends the session.
* The firewall still only connects out: its terminal helper opens a WebSocket to the agent port with
  the same certificate pin and device token as every other request.
* Sessions end after 15 minutes without input and after 2 hours.
* Approval, wrong codes, connect and close are in the audit log. The terminal output is recorded on the
  server (`data/terminal/<id>.cast`, asciicast v2, up to 10 MB per session) and can be replayed or
  downloaded from the firewall's page by any admin. Keystrokes are not recorded separately; what the
  shell echoes is. Recordings are not deleted automatically.
* The terminal page relaxes the Content Security Policy for styles only (`style-src 'unsafe-inline'`,
  needed by xterm.js); scripts stay restricted to the console's own files.

Policies are validated on both ends; `config_set` cannot touch users, groups, authentication servers,
certificates, the agent's own settings or anything that runs commands (shellcmd, cron, the Filer and Sudo
packages), nor any path above those (`system` as a whole), and only admins can create or change one.
A backup restore keeps the firewall's current ComSense settings, so it cannot turn local permissions
back on. Re-enrolling an existing firewall always waits for an admin's approval. Every configuration change (policies and restores) is
verified afterwards and kept on probation; if the firewall loses contact with the server, the agent
restores the previous configuration on its own, also after a reboot.

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

## Two-factor sign-in

* Users turn on an **authenticator app** (TOTP, RFC 6238: 6 digits, 30 s) and/or **email codes** on
  their Account page. Each is confirmed with a first code before it is switched on. TOTP secrets are
  encrypted with a key derived from `CSFM_SECRET_KEY`; a TOTP code is accepted once (its time step is
  remembered). Ten one-time recovery codes are created with the app, stored hashed and shown once.
* Email codes are 6 digits, single use, valid 10 minutes, kept hashed in the signed session; sending is
  rate limited.
* After a correct password the session holds only a pending sign-in (10 minutes). The second step allows
  5 wrong codes before starting over, plus a per-user limit across sign-ins. Failures are audited.
* **Settings → Security** requires two-factor sign-in for nobody, admins or everyone, and chooses the
  allowed methods. Users who must use it but have not set it up can only reach their Account page until
  they do. Turning off a method needs the password; the last one cannot be turned off while required.
  Admins can reset a user's two-factor sign-in on Settings > Users (audited).

## Recommendations

* Require two-factor sign-in under Settings → Security (at least for admins).
* Restrict the web console (port 443) to admins: source allow-list, VPN, or SSO in your proxy.
  Firewalls never need it. Only the agent port has to be reachable from the internet.
* Use short-lived, single-customer keys with approval for each rollout, and revoke them after.
* Keep `CSFM_BACKUP_ENCRYPTION_KEY` and `CSFM_SECRET_KEY` in a secrets manager and back them up
  separately from the data.
