<?php
/*
 * ComSense agent - shared helpers.
 *
 * This file must not depend on pfSense runtime functions other than the
 * config accessors wrapped below, so it can be exercised outside a firewall.
 */

if (!defined('CSFM_AGENT_VERSION')) {
	define('CSFM_AGENT_VERSION', '0.2.13');
}
if (!defined('CSFM_DB_DIR')) {
	/* Overridable so the agent can be exercised outside a firewall. */
	define('CSFM_DB_DIR', '/var/db/comsense');
}
define('CSFM_CREDENTIALS_FILE', CSFM_DB_DIR . '/credentials.json');
define('CSFM_STATE_FILE', CSFM_DB_DIR . '/state.json');
define('CSFM_INTERVAL_FILE', CSFM_DB_DIR . '/interval');
define('CSFM_CA_FILE', CSFM_DB_DIR . '/server-ca.pem');
define('CSFM_CONFIG_PATH', 'installedpackages/comsense/config/0');
define('CSFM_SYSTEM_CA_BUNDLE', '/etc/ssl/cert.pem');
/* pkg(8) on pfSense; /usr/sbin/pkg is only FreeBSD's bootstrap stub. */
define('CSFM_PKG', '/usr/local/sbin/pkg-static');
if (!defined('CSFM_UPGRADE_BIN')) {
	/* pfSense's own update tool (System > Update uses it too). */
	define('CSFM_UPGRADE_BIN', '/usr/local/sbin/pfSense-upgrade');
}

/*
 * The agent runs as a daemon started at boot, without root's login environment. pfSense's tools
 * need it: pfSense-upgrade calls its helpers by name (PATH), and pfSense-repoc, which asks Netgate
 * which versions this firewall may upgrade to, finds the CA certificates through SSL_CERT_DIR;
 * without it no new pfSense version is ever reported. Give every command the agent runs root's
 * login environment (as in a shell on the firewall).
 */
function csfm_fix_environment() {
	$want = array('/sbin', '/bin', '/usr/sbin', '/usr/bin', '/usr/local/sbin', '/usr/local/bin');
	$have = array_filter(explode(':', (string)getenv('PATH')));
	putenv('PATH=' . implode(':', array_unique(array_merge($want, $have))));
	$defaults = array('HOME' => '/root', 'USER' => 'root', 'LOGNAME' => 'root', 'LANG' => 'C.UTF-8');
	if (is_dir('/etc/ssl/certs')) {
		$defaults['SSL_CERT_DIR'] = '/etc/ssl/certs/';
	}
	foreach ($defaults as $name => $value) {
		if ((string)getenv($name) === '') {
			putenv("{$name}={$value}");
		}
	}
}
csfm_fix_environment();

/* Actions the firewall owner can allow in the package settings. */
$csfm_capability_fields = array(
	'backup' => 'allow_backup',
	'policy' => 'allow_policy',
	'upgrade' => 'allow_upgrade',
	'packages' => 'allow_packages',
	'services' => 'allow_services',
	'restore' => 'allow_restore',
	'reboot' => 'allow_reboot',
	'shell' => 'allow_shell',
);

function csfm_log($message, $priority = LOG_NOTICE) {
	static $opened = false;
	if (!$opened) {
		openlog('comsense', LOG_PID, LOG_DAEMON);
		$opened = true;
	}
	syslog($priority, $message);
	if (defined('CSFM_VERBOSE') && CSFM_VERBOSE) {
		fwrite(STDERR, $message . "\n");
	}
}

/* ---------------------------------------------------------------- config access */

function csfm_cfg_get($path, $default = null) {
	if (function_exists('config_get_path')) {
		return config_get_path($path, $default);
	}
	global $config;
	$node = $config;
	foreach (explode('/', $path) as $part) {
		if (!is_array($node) || !array_key_exists($part, $node)) {
			return $default;
		}
		$node = $node[$part];
	}
	return $node;
}

function csfm_cfg_set($path, $value) {
	if (function_exists('config_set_path')) {
		config_set_path($path, $value);
		return;
	}
	global $config;
	$node = &$config;
	foreach (explode('/', $path) as $part) {
		if (!isset($node[$part]) || !is_array($node[$part])) {
			$node[$part] = array();
		}
		$node = &$node[$part];
	}
	$node = $value;
}

function csfm_cfg_del($path) {
	if (function_exists('config_del_path')) {
		config_del_path($path);
		return;
	}
	global $config;
	$parts = explode('/', $path);
	$last = array_pop($parts);
	$node = &$config;
	foreach ($parts as $part) {
		if (!isset($node[$part]) || !is_array($node[$part])) {
			return;
		}
		$node = &$node[$part];
	}
	unset($node[$last]);
}

function csfm_settings() {
	$s = csfm_cfg_get(CSFM_CONFIG_PATH, array());
	return is_array($s) ? $s : array();
}

function csfm_capabilities($settings = null) {
	global $csfm_capability_fields;
	$settings = ($settings === null) ? csfm_settings() : $settings;
	$caps = array();
	foreach ($csfm_capability_fields as $cap => $field) {
		if (!empty($settings[$field])) {
			$caps[] = $cap;
		}
	}
	return $caps;
}

function csfm_has_capability($cap) {
	return in_array($cap, csfm_capabilities(), true);
}

/* ----------------------------------------------------------------- local state */

function csfm_ensure_db_dir() {
	if (!is_dir(CSFM_DB_DIR)) {
		mkdir(CSFM_DB_DIR, 0700, true);
	}
	chmod(CSFM_DB_DIR, 0700);
}

function csfm_read_json($file, $default = array()) {
	if (!is_readable($file)) {
		return $default;
	}
	$data = json_decode((string)file_get_contents($file), true);
	return is_array($data) ? $data : $default;
}

function csfm_write_json($file, $data) {
	csfm_ensure_db_dir();
	$tmp = $file . '.tmp';
	file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
	chmod($tmp, 0600);
	rename($tmp, $file);
}

function csfm_credentials() {
	return csfm_read_json(CSFM_CREDENTIALS_FILE, array());
}

function csfm_save_credentials($creds) {
	csfm_write_json(CSFM_CREDENTIALS_FILE, $creds);
}

function csfm_forget_credentials() {
	@unlink(CSFM_CREDENTIALS_FILE);
	$state = csfm_state();
	unset($state['last_checkin'], $state['device_status']);
	$state['policies'] = array();
	csfm_save_state($state);
}

function csfm_is_enrolled() {
	$c = csfm_credentials();
	return !empty($c['token']) && !empty($c['device_id']);
}

function csfm_state() {
	$state = csfm_read_json(CSFM_STATE_FILE, array());
	if (!isset($state['policies']) || !is_array($state['policies'])) {
		$state['policies'] = array();
	}
	return $state;
}

function csfm_save_state($state) {
	csfm_write_json(CSFM_STATE_FILE, $state);
}

function csfm_state_set($key, $value) {
	$state = csfm_state();
	$state[$key] = $value;
	csfm_save_state($state);
}

/* ------------------------------------------------------------------- utilities */

function csfm_normalize_url($url) {
	$url = rtrim(trim((string)$url), '/');
	$parts = parse_url($url);
	if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
		return false;
	}
	if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
		return false;
	}
	return $url;
}

/*
 * Enrollment codes ("csfm1.<base64url JSON>") carry the agent server URL, the
 * enrollment key and, for a self-issued server certificate, its public key pin.
 * Returns array(url, key, pin) or false for a bare key.
 */
function csfm_parse_enrollment_code($code) {
	$code = trim((string)$code);
	if (strpos($code, 'csfm1.') !== 0) {
		return false;
	}
	$b64 = strtr(substr($code, 6), '-_', '+/');
	$json = base64_decode($b64 . str_repeat('=', (4 - strlen($b64) % 4) % 4), true);
	$data = ($json === false) ? null : json_decode($json, true);
	if (!is_array($data) || empty($data['url']) || empty($data['key'])) {
		return null;
	}
	return array((string)$data['url'], (string)$data['key'], (string)($data['pin'] ?? ''));
}

/* Apply an enrollment code to a settings array; returns the bare key, or throws. */
function csfm_apply_enrollment_code(&$settings, $value) {
	$parsed = csfm_parse_enrollment_code($value);
	if ($parsed === null) {
		throw new Exception('The enrollment code is damaged; copy it again from the server.');
	}
	if ($parsed === false) {
		return trim((string)$value);
	}
	list($url, $key, $pin) = $parsed;
	$settings['server_url'] = $url;
	$settings['pin_sha256'] = $pin;
	return $key;
}

/* Run a command with a hard timeout; returns array(exit code, combined output). */
function csfm_exec($cmd, $timeout = 600) {
	$full = '/usr/bin/timeout ' . (int)$timeout . ' ' . $cmd . ' 2>&1';
	$out = array();
	$rc = 0;
	exec($full, $out, $rc);
	return array($rc, implode("\n", $out));
}

function csfm_truncate($text, $limit = 60000) {
	return strlen($text) > $limit ? substr($text, -$limit) : $text;
}
