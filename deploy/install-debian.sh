#!/usr/bin/env bash
#
# Install the PfManager server on Debian 12+ or Ubuntu 22.04+ without Docker:
# PostgreSQL, the app under systemd, and Caddy for automatic HTTPS on port 443.
#
#   sudo ./deploy/install-debian.sh pfmanager.example.com admin@example.com
#
# Re-running it upgrades the application and keeps existing keys and data.
set -euo pipefail

DOMAIN="${1:?usage: $0 <domain> [acme-email]}"
EMAIL="${2:-}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/pfmanager
ENV_FILE=/etc/pfmanager/pfmanager.env

if [[ $EUID -ne 0 ]]; then
	echo "Run as root" >&2
	exit 1
fi

apt-get update
apt-get install -y python3 python3-venv postgresql caddy openssl

id pfmanager >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin pfmanager
install -d -o pfmanager -g pfmanager -m 0700 /var/lib/pfmanager
install -d -m 0750 -g pfmanager /etc/pfmanager
install -d "$APP_DIR"
rm -rf "$APP_DIR/server"
cp -r "$SRC/server" "$APP_DIR/server"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip >/dev/null
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/server/requirements.txt"

if [[ ! -f "$ENV_FILE" ]]; then
	DB_PASS="$(openssl rand -hex 24)"
	ADMIN_PASS="$(openssl rand -base64 18)"
	sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
CREATE ROLE pfmanager LOGIN PASSWORD '${DB_PASS}';
CREATE DATABASE pfmanager OWNER pfmanager;
SQL
	{
		echo "PFM_DATABASE_URL=postgresql+psycopg://pfmanager:${DB_PASS}@127.0.0.1:5432/pfmanager"
		echo "PFM_PUBLIC_URL=https://${DOMAIN}"
		echo "PFM_DATA_DIR=/var/lib/pfmanager"
		(cd "$APP_DIR/server" && "$APP_DIR/venv/bin/python" -m app.cli keygen)
		echo "PFM_INITIAL_ADMIN_USER=admin"
		echo "PFM_INITIAL_ADMIN_PASSWORD=${ADMIN_PASS}"
	} > "$ENV_FILE"
	chmod 0640 "$ENV_FILE"
	chgrp pfmanager "$ENV_FILE"
	echo
	echo "Initial login: admin / ${ADMIN_PASS}"
	echo "Back up ${ENV_FILE}: without PFM_BACKUP_ENCRYPTION_KEY stored backups cannot be decrypted."
	echo
fi

install -m 0644 "$SRC/deploy/pfmanager.service" /etc/systemd/system/pfmanager.service

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
systemctl enable --now pfmanager.service
systemctl restart pfmanager.service
systemctl reload caddy || systemctl restart caddy

echo "PfManager is starting at https://${DOMAIN}"
