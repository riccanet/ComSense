<?php
/*
 * pfmanager.inc
 *
 * pfSense package hooks for the PfManager agent: install/deinstall, settings
 * validation (which performs enrollment) and resync (which restarts the agent).
 */

require_once('config.inc');
require_once('globals.inc');
require_once('util.inc');
require_once('service-utils.inc');
require_once('/usr/local/pkg/pfmanager/lib/agent.inc');

define('PFM_PIDFILE', '/var/run/pfmanager_agent.pid');

function pfmanager_install() {
	pfm_ensure_db_dir();
	pfmanager_write_rcfile();
}

function pfmanager_deinstall() {
	pfmanager_stop();
	unlink_if_exists('/usr/local/etc/rc.d/pfmanager.sh');
	/* Keep /var/db/pfmanager so a reinstall keeps its identity; remove it by hand to fully reset. */
}

function pfmanager_write_rcfile() {
	$start = "/usr/sbin/daemon -f -P " . PFM_PIDFILE . " /usr/local/sbin/pfmanager-agentd";
	$stop = "if [ -f " . PFM_PIDFILE . " ]; then\n"
	    . "\t\t/bin/pkill -F " . PFM_PIDFILE . "\n"
	    . "\t\t/bin/rm -f " . PFM_PIDFILE . "\n"
	    . "\tfi";
	write_rcfile(array(
		'file' => 'pfmanager.sh',
		'start' => $start,
		'stop' => $stop,
	));
}

function pfmanager_running() {
	return isvalidpid(PFM_PIDFILE);
}

function pfmanager_stop() {
	if (file_exists('/usr/local/etc/rc.d/pfmanager.sh')) {
		mwexec('/usr/local/etc/rc.d/pfmanager.sh stop');
	}
}

function pfmanager_start() {
	if (!pfmanager_running()) {
		mwexec('/usr/local/etc/rc.d/pfmanager.sh start');
	}
}

/* Write the optional private CA bundle used to verify the server. */
function pfmanager_write_ca($settings) {
	pfm_ensure_db_dir();
	$pem = isset($settings['ca_cert']) ? base64_decode($settings['ca_cert'], true) : '';
	if ($pem !== false && trim($pem) !== '') {
		file_put_contents(PFM_CA_FILE, $pem);
		chmod(PFM_CA_FILE, 0600);
	} else {
		@unlink(PFM_CA_FILE);
	}
}

function pfmanager_validate_input(&$post, &$input_errors) {
	if (empty($post['enable'])) {
		return;
	}
	$url = pfm_normalize_url($post['server_url'] ?? '');
	if ($url === false) {
		$input_errors[] = gettext('The server URL must start with https:// and contain only a host, optional port and path.');
		return;
	}
	$post['server_url'] = $url;

	if (!empty($post['ca_cert'])) {
		$pem = $post['ca_cert'];
		if (strpos($pem, '-----BEGIN CERTIFICATE-----') === false || openssl_x509_read($pem) === false) {
			$input_errors[] = gettext('The CA certificate is not a valid PEM certificate.');
			return;
		}
	}
	if (!empty($post['pin_sha256'])) {
		foreach (preg_split('/[\s,;]+/', trim($post['pin_sha256'])) as $pin) {
			$pin = preg_replace('#^sha256//#', '', $pin);
			if ($pin !== '' && (strlen(base64_decode($pin, true) ?: '') !== 32)) {
				$input_errors[] = gettext('Each public key pin must be a base64 SHA-256 digest.');
				return;
			}
		}
	}

	$key = trim($post['enrollment_key'] ?? '');
	if ($key === '') {
		if (!pfm_is_enrolled()) {
			$input_errors[] = gettext('Enter the enrollment key from the management server to connect this firewall.');
		}
		return;
	}

	/* Enroll now so a wrong URL, certificate or key is reported on this page. */
	$settings = $post;
	$settings['ca_cert'] = !empty($post['ca_cert']) ? base64_encode($post['ca_cert']) : '';
	pfmanager_write_ca($settings);
	try {
		pfm_enroll($settings, $key);
		/* Never persist the enrollment key in config.xml (or in its backups). */
		$post['enrollment_key'] = '';
	} catch (Exception $e) {
		$input_errors[] = sprintf(gettext('Enrollment failed: %s'), $e->getMessage());
	}
}

function pfmanager_resync() {
	$settings = pfm_settings();
	pfmanager_write_ca($settings);
	pfmanager_write_rcfile();
	pfmanager_stop();
	if (!empty($settings['enable'])) {
		pfmanager_start();
	}
}
