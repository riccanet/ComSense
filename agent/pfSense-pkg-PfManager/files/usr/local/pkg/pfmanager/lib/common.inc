<?php
/*
 * PfManager agent - shared helpers.
 *
 * This file must not depend on pfSense runtime functions other than the
 * config accessors wrapped below, so it can be exercised outside a firewall.
 */

define('PFM_AGENT_VERSION', '0.1.0');
if (!defined('PFM_DB_DIR')) {
	/* Overridable so the agent can be exercised outside a firewall. */
	define('PFM_DB_DIR', '/var/db/pfmanager');
}
define('PFM_CREDENTIALS_FILE', PFM_DB_DIR . '/credentials.json');
define('PFM_STATE_FILE', PFM_DB_DIR . '/state.json');
define('PFM_INTERVAL_FILE', PFM_DB_DIR . '/interval');
define('PFM_CA_FILE', PFM_DB_DIR . '/server-ca.pem');
define('PFM_CONFIG_PATH', 'installedpackages/pfmanager/config/0');
define('PFM_SYSTEM_CA_BUNDLE', '/etc/ssl/cert.pem');

/* Actions the firewall owner can allow in the package settings. */
$pfm_capability_fields = array(
	'backup' => 'allow_backup',
	'policy' => 'allow_policy',
	'upgrade' => 'allow_upgrade',
	'packages' => 'allow_packages',
	'services' => 'allow_services',
	'restore' => 'allow_restore',
	'reboot' => 'allow_reboot',
);

function pfm_log($message, $priority = LOG_NOTICE) {
	static $opened = false;
	if (!$opened) {
		openlog('pfmanager', LOG_PID, LOG_DAEMON);
		$opened = true;
	}
	syslog($priority, $message);
	if (defined('PFM_VERBOSE') && PFM_VERBOSE) {
		fwrite(STDERR, $message . "\n");
	}
}

/* ---------------------------------------------------------------- config access */

function pfm_cfg_get($path, $default = null) {
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

function pfm_cfg_set($path, $value) {
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

function pfm_cfg_del($path) {
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

function pfm_settings() {
	$s = pfm_cfg_get(PFM_CONFIG_PATH, array());
	return is_array($s) ? $s : array();
}

function pfm_capabilities($settings = null) {
	global $pfm_capability_fields;
	$settings = ($settings === null) ? pfm_settings() : $settings;
	$caps = array();
	foreach ($pfm_capability_fields as $cap => $field) {
		if (!empty($settings[$field])) {
			$caps[] = $cap;
		}
	}
	return $caps;
}

function pfm_has_capability($cap) {
	return in_array($cap, pfm_capabilities(), true);
}

/* ----------------------------------------------------------------- local state */

function pfm_ensure_db_dir() {
	if (!is_dir(PFM_DB_DIR)) {
		mkdir(PFM_DB_DIR, 0700, true);
	}
	chmod(PFM_DB_DIR, 0700);
}

function pfm_read_json($file, $default = array()) {
	if (!is_readable($file)) {
		return $default;
	}
	$data = json_decode((string)file_get_contents($file), true);
	return is_array($data) ? $data : $default;
}

function pfm_write_json($file, $data) {
	pfm_ensure_db_dir();
	$tmp = $file . '.tmp';
	file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
	chmod($tmp, 0600);
	rename($tmp, $file);
}

function pfm_credentials() {
	return pfm_read_json(PFM_CREDENTIALS_FILE, array());
}

function pfm_save_credentials($creds) {
	pfm_write_json(PFM_CREDENTIALS_FILE, $creds);
}

function pfm_forget_credentials() {
	@unlink(PFM_CREDENTIALS_FILE);
	$state = pfm_state();
	unset($state['last_checkin'], $state['device_status']);
	$state['policies'] = array();
	pfm_save_state($state);
}

function pfm_is_enrolled() {
	$c = pfm_credentials();
	return !empty($c['token']) && !empty($c['device_id']);
}

function pfm_state() {
	$state = pfm_read_json(PFM_STATE_FILE, array());
	if (!isset($state['policies']) || !is_array($state['policies'])) {
		$state['policies'] = array();
	}
	return $state;
}

function pfm_save_state($state) {
	pfm_write_json(PFM_STATE_FILE, $state);
}

function pfm_state_set($key, $value) {
	$state = pfm_state();
	$state[$key] = $value;
	pfm_save_state($state);
}

/* ------------------------------------------------------------------- utilities */

function pfm_normalize_url($url) {
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

/* Run a command with a hard timeout; returns array(exit code, combined output). */
function pfm_exec($cmd, $timeout = 600) {
	$full = '/usr/bin/timeout ' . (int)$timeout . ' ' . $cmd . ' 2>&1';
	$out = array();
	$rc = 0;
	exec($full, $out, $rc);
	return array($rc, implode("\n", $out));
}

function pfm_truncate($text, $limit = 60000) {
	return strlen($text) > $limit ? substr($text, -$limit) : $text;
}
