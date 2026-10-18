<?php
/*
 * comsense.inc
 *
 * pfSense package hooks for the ComSense agent: install/deinstall, settings
 * validation (which performs enrollment) and resync (which restarts the agent).
 */

require_once('config.inc');
require_once('globals.inc');
require_once('util.inc');
require_once('service-utils.inc');
require_once('/usr/local/pkg/comsense/lib/agent.inc');

define('CSFM_PIDFILE', '/var/run/comsense_agent.pid');
define('CSFM_WATCHDOG_PIDFILE', '/var/run/comsense_watchdog.pid');

function comsense_install() {
	csfm_ensure_db_dir();
	comsense_remove_stale_registration();
	comsense_refresh_service_entry();
	comsense_write_rcfile();
}

/*
 * pfSense keeps an existing service entry on reinstall, so a changed <service>
 * in comsense.xml would never take effect. Drop ours here: the installer adds it
 * again from comsense.xml right after this hook. (Up to 0.1.6 its status command
 * called comsense_running(), which the GUI cannot see, and broke the dashboard.)
 */
function comsense_refresh_service_entry() {
	$removed = false;
	foreach (config_get_path('installedpackages/service', array()) as $idx => $svc) {
		if (is_array($svc) && trim($svc['name'] ?? '') === 'comsense') {
			config_del_path("installedpackages/service/{$idx}");
			$removed = true;
		}
	}
	if ($removed) {
		write_config('ComSense: refreshing the agent service entry');
	}
}

/*
 * 0.1.0 registered itself as "comsense" while pfSense looks it up as "ComSense",
 * so its install aborted and left that entry behind in config.xml. Drop it.
 */
function comsense_remove_stale_registration() {
	$removed = false;
	foreach (config_get_path('installedpackages/package', array()) as $idx => $p) {
		if (is_array($p) && ($p['name'] ?? '') === 'comsense' && empty($p['internal_name'])) {
			/* By key and without renumbering, like pfSense does: the installer still holds our entry's key. */
			config_del_path("installedpackages/package/{$idx}");
			$removed = true;
		}
	}
	if ($removed) {
		write_config('ComSense: removed a stale package entry left by version 0.1.0');
	}
}

function comsense_deinstall() {
	/* A pfSense upgrade removes the package too; only a deliberate removal stops the boot-time reinstall. */
	if (!csfm_removal_is_upgrade()) {
		csfm_disable_recovery();
	}
	comsense_stop();
	unlink_if_exists('/usr/local/etc/rc.d/comsense.sh');
	/* Keep /var/db/comsense so a reinstall keeps its identity; remove it by hand to fully reset. */
}

function comsense_write_rcfile() {
	/* The agent loop, and the watchdog that rolls back changes that cut the firewall off (lib/guard.inc). */
	$start = "/usr/sbin/daemon -f -P " . CSFM_PIDFILE . " /usr/local/sbin/comsense-agentd\n"
	    . "\t/usr/sbin/daemon -f -P " . CSFM_WATCHDOG_PIDFILE . " /usr/local/sbin/comsense-watchdogd";
	$stop = "";
	foreach (array(CSFM_PIDFILE, CSFM_WATCHDOG_PIDFILE) as $pidfile) {
		$stop .= "if [ -f {$pidfile} ]; then\n"
		    . "\t\t/bin/pkill -F {$pidfile}\n"
		    . "\t\t/bin/rm -f {$pidfile}\n"
		    . "\tfi\n\t";
	}
	write_rcfile(array(
		'file' => 'comsense.sh',
		'start' => $start,
		'stop' => rtrim($stop),
	));
}

function comsense_running() {
	return isvalidpid(CSFM_PIDFILE);
}

function comsense_stop() {
	if (file_exists('/usr/local/etc/rc.d/comsense.sh')) {
		mwexec('/usr/local/etc/rc.d/comsense.sh stop');
	}
}

function comsense_start() {
	if (!comsense_running()) {
		mwexec('/usr/local/etc/rc.d/comsense.sh start');
	}
}

/* Write the optional private CA bundle used to verify the server. */
function comsense_write_ca($settings) {
	csfm_ensure_db_dir();
	$pem = isset($settings['ca_cert']) ? base64_decode($settings['ca_cert'], true) : '';
	if ($pem !== false && trim($pem) !== '') {
		file_put_contents(CSFM_CA_FILE, $pem);
		chmod(CSFM_CA_FILE, 0600);
	} else {
		@unlink(CSFM_CA_FILE);
	}
}

function comsense_validate_input(&$post, &$input_errors) {
	if (empty($post['enable'])) {
		return;
	}
	try {
		$key = csfm_apply_enrollment_code($post, $post['enrollment_key'] ?? '');
	} catch (Exception $e) {
		$input_errors[] = gettext($e->getMessage());
		return;
	}
	$url = csfm_normalize_url($post['server_url'] ?? '');
	if ($url === false) {
		$input_errors[] = gettext('Paste the enrollment code from the server, or enter an https:// server URL (host and optional port).');
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

	if ($key === '') {
		if (!csfm_is_enrolled()) {
			$input_errors[] = gettext('Paste the enrollment code from the management server to connect this firewall.');
		}
		return;
	}

	/* Enroll now so a wrong URL, certificate or key is reported on this page. */
	$settings = $post;
	$settings['ca_cert'] = !empty($post['ca_cert']) ? base64_encode($post['ca_cert']) : '';
	comsense_write_ca($settings);
	try {
		csfm_enroll($settings, $key);
		/* Never persist the enrollment key in config.xml (or in its backups). */
		$post['enrollment_key'] = '';
	} catch (Exception $e) {
		$input_errors[] = sprintf(gettext('Enrollment failed: %s'), $e->getMessage());
	}
}

function comsense_resync() {
	$settings = csfm_settings();
	comsense_write_ca($settings);
	comsense_write_rcfile();
	comsense_stop();
	if (!empty($settings['enable'])) {
		comsense_start();
	}
}
