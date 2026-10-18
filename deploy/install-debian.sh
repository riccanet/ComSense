#!/usr/bin/env bash
#
# Install the ComSense server on Debian 12+ or Ubuntu 22.04+ without Docker:
# PostgreSQL, the app under systemd (web console + agent listener with its own
# TLS on port 8443) and, unless you bring your own proxy, Caddy for the console.
#
#   Option 1, bundled Caddy (console on https://<domain>, Let's Encrypt):
#     sudo ./deploy/install-debian.sh comsense.example.com [admin@example.com]
#
#   Option 2, bring your own reverse proxy (console on plain HTTP for your proxy):
#     sudo ./deploy/install-debian.sh --byo-proxy[=BIND_ADDRESS] comsense.example.com
#     BIND_ADDRESS defaults to 127.0.0.1; use a LAN/VPN address if the proxy is on
#     another host. Point the proxy at http://BIND_ADDRESS:8000.
#
# Either way, forward/open TCP 8443 for firewalls. Re-running upgrades the
# application and keeps existing keys and data.
set -euo pipefail

BYO_PROXY=0
WEB_BIND=127.0.0.1
ARGS=()
for arg in "$@"; do
	case "$arg" in
		--byo-proxy) BYO_PROXY=1 ;;
		--byo-proxy=*) BYO_PROXY=1; WEB_BIND="${arg#*=}" ;;
		*) ARGS+=("$arg") ;;
	esac
done
DOMAIN="${ARGS[0]:?usage: $0 [--byo-proxy[=BIND_ADDRESS]] <domain> [acme-email]}"
EMAIL="${ARGS[1]:-}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/comsense
ENV_FILE=/etc/comsense/comsense.env

# Set KEY=VALUE in the env file, adding the line if an older install lacks it.
set_env() {
	if grep -q "^$1=" "$ENV_FILE"; then
		sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
	else
		echo "$1=$2" >> "$ENV_FILE"
	fi
}

if [[ $EUID -ne 0 ]]; then
	echo "Run as root" >&2
	exit 1
fi

apt-get update
PACKAGES=(python3 python3-venv postgresql openssl)
if [[ $BYO_PROXY -eq 0 ]]; then
	PACKAGES+=(caddy)
fi
apt-get install -y "${PACKAGES[@]}"

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

if [[ $BYO_PROXY -eq 0 ]]; then
	# Caddy runs on this host, so only it may reach the console port.
	set_env CSFM_WEB_HOST 127.0.0.1
	set_env CSFM_FORWARDED_ALLOW_IPS 127.0.0.1
	{
		if [[ -n "$EMAIL" ]]; then
			printf '{\n\temail %s\n}\n\n' "$EMAIL"
		fi
		cat <<CADDY
${DOMAIN} {
	encode gzip
	reverse_proxy 127.0.0.1:8000
	header {
		-Server
	}
}
CADDY
	} > /etc/caddy/Caddyfile
else
	set_env CSFM_WEB_HOST "$WEB_BIND"
	set_env CSFM_FORWARDED_ALLOW_IPS "*"
fi

systemctl daemon-reload
systemctl enable --now comsense.service
systemctl restart comsense.service
if [[ $BYO_PROXY -eq 0 ]]; then
	systemctl reload caddy || systemctl restart caddy
fi

echo "First sign-in: user admin, one-time password from: journalctl -u comsense | grep -A1 'username:'"
echo "Agents: https://${DOMAIN}:8443 (forward/open TCP 8443 to this host)."
if [[ $BYO_PROXY -eq 0 ]]; then
	echo "Web console: https://${DOMAIN} via Caddy (open 80 and 443; restrict 443 to admins if you like)."
else
	echo "Web console: point your reverse proxy for https://${DOMAIN} at http://${WEB_BIND}:8000"
fi
