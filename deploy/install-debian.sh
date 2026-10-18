#!/usr/bin/env bash
#
# Install the ComSense server on Debian 12+ or Ubuntu 22.04+ without Docker:
# PostgreSQL, the app under systemd, Caddy for the web console on port 443, and the
# agent listener (its own TLS) on CSFM_AGENT_PORT, default 8443. Open/forward both.
#
#   sudo ./deploy/install-debian.sh comsense.example.com admin@example.com
#
# Re-running it upgrades the application and keeps existing keys and data.
set -euo pipefail

DOMAIN="${1:?usage: $0 <domain> [acme-email]}"
EMAIL="${2:-}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/comsense
ENV_FILE=/etc/comsense/comsense.env

if [[ $EUID -ne 0 ]]; then
	echo "Run as root" >&2
	exit 1
fi

apt-get update
apt-get install -y python3 python3-venv postgresql caddy openssl

id comsense >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin comsense
install -d -o comsense -g comsense -m 0700 /var/lib/comsense
install -d -m 0750 -g comsense /etc/comsense
install -d "$APP_DIR"
rm -rf "$APP_DIR/server"
cp -r "$SRC/server" "$APP_DIR/server"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip >/dev/null
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/server/requirements.txt"

if [[ ! -f "$ENV_FILE" ]]; then
	DB_PASS="$(openssl rand -hex 24)"
	sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE comsense LOGIN PASSWORD '${DB_PASS}';
CREATE DATABASE comsense OWNER comsense;
SQL
	{
		echo "CSFM_DATABASE_URL=postgresql+psycopg://comsense:${DB_PASS}@127.0.0.1:5432/comsense"
		echo "CSFM_PUBLIC_URL=https://${DOMAIN}"
		echo "CSFM_DATA_DIR=/var/lib/comsense"
		(cd "$APP_DIR/server" && "$APP_DIR/venv/bin/python" -m app.cli keygen)
		echo "CSFM_INITIAL_ADMIN_USER=admin"
	} > "$ENV_FILE"
	chmod 0640 "$ENV_FILE"
	chgrp comsense "$ENV_FILE"
	echo
	echo "Back up ${ENV_FILE}: without CSFM_BACKUP_ENCRYPTION_KEY stored backups cannot be decrypted."
	echo
fi

install -m 0644 "$SRC/deploy/comsense.service" /etc/systemd/system/comsense.service

{
	if [[ -n "$EMAIL" ]]; then
		printf '{\n\temail %s\n}\n\n' "$EMAIL"
	fi
	cat <<CADDY
${DOMAIN} {
	encode gzip
	request_body {
		max_size 40MB
	}
	reverse_proxy 127.0.0.1:8000
	header {
		-Server
	}
}
CADDY
} > /etc/caddy/Caddyfile

systemctl daemon-reload
systemctl enable --now comsense.service
systemctl restart comsense.service
systemctl reload caddy || systemctl restart caddy

echo "First sign-in: user admin, one-time password from: journalctl -u comsense | grep -A1 'username:'"
echo "ComSense is starting. Web console: https://${DOMAIN}  Agents: https://${DOMAIN}:8443"
echo "Forward/open TCP 443 (console) and 8443 (agents). Restrict 443 to admins if you like."
