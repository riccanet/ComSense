<?php
/*
 * ComSense agent - shared helpers.
 *
 * This file must not depend on pfSense runtime functions other than the
 * config accessors wrapped below, so it can be exercised outside a firewall.
 */

if (!defined('CSFM_AGENT_VERSION')) {
	define('CSFM_AGENT_VERSION', '0.2.43');
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
if (!defined('CSFM_PKG')) {
	define('CSFM_PKG', '/usr/local/sbin/pkg-static');
}
if (!defined('CSFM_PFCTL')) {
	define('CSFM_PFCTL', '/sbin/pfctl');
}
if (!defined('CSFM_RULES_DEBUG')) {
	/* The ruleset pfSense generates from config.xml and loads into pf (filter.inc). */
	define('CSFM_RULES_DEBUG', '/tmp/rules.debug');
}
if (!defined('CSFM_FILTER_SYNC_BIN')) {
	/* pfSense's own "reload the rules now" script; it loads everything filter.inc needs (shaper.inc...). */
	define('CSFM_FILTER_SYNC_BIN', '/etc/rc.filter_configure_sync');
}
if (!defined('CSFM_PHP_BIN')) {
	define('CSFM_PHP_BIN', '/usr/local/bin/php');
}
if (!defined('CSFM_PFB_SCRIPT')) {
	/* pfBlockerNG's command line: "dc" downloads the MaxMind GeoIP database, "updateip" is Force Reload IP. */
	define('CSFM_PFB_SCRIPT', '/usr/local/www/pfblockerng/pfblockerng.php');
}
if (!defined('CSFM_GEOIP_DB')) {
	/* pfBlockerNG's MaxMind country database: present once it has downloaded it. */
	define('CSFM_GEOIP_DB', '/usr/local/share/GeoIP/GeoLite2-Country.mmdb');
}
if (!defined('CSFM_UPGRADE_BIN')) {
	/* pfSense's own update tool (System > Update uses it too). */
	define('CSFM_UPGRADE_BIN', '/usr/local/sbin/pfSense-upgrade');
}

/*
 * The environment pfSense's tools are run with: exactly what a root shell on the firewall has
 * (the remote terminal starts its shell with these, and pfSense's shell startup adds SSL_CERT_DIR),
 * and nothing inherited from the agent daemon. pfSense-upgrade calls its helpers by name (PATH),
 * and pfSense-repoc, which asks Netgate which versions the firewall may upgrade to, verifies
 * Netgate's certificate against SSL_CERT_DIR. Run from the daemon's own environment, plus these
 * variables, it still failed ("certificate verify failed"); from this clean one it works.
 */
function csfm_clean_environment() {
	$env = array(
		'PATH' => '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin',
		'HOME' => '/root',
		'USER' => 'root',
		'LOGNAME' => 'root',
		'LANG' => 'C.UTF-8',
	);
	if (is_dir('/etc/ssl/certs')) {
		$env['SSL_CERT_DIR'] = '/etc/ssl/certs/';
	}
	return $env;
}

/*
 * "/usr/bin/env -i NAME=value ...", put in front of every command the agent runs, so it gets that
 * environment and nothing else, even through wrappers (pfSense's mwexec, daemon(8), lockf(1)).
 */
function csfm_env_prefix() {
	$parts = array();
	foreach (csfm_clean_environment() as $name => $value) {
		$parts[] = escapeshellarg("{$name}={$value}");
	}
	return '/usr/bin/env -i ' . implode(' ', $parts) . ' ';
}

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

/* PHP before 8.1 (older pfSense CE). */
if (!function_exists('array_is_list')) {
	function array_is_list(array $a) {
		return $a === array() || array_keys($a) === range(0, count($a) - 1);
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
	$full = csfm_env_prefix() . '/usr/bin/timeout ' . (int)$timeout . ' ' . $cmd . ' 2>&1';
	$out = array();
	$rc = 0;
	exec($full, $out, $rc);
	return array($rc, implode("\n", $out));
}

if (!defined('CSFM_HEARTBEAT_EVERY')) {
	/* While a long command runs inside a task, report progress this often (seconds), so the firewall is not
	   taken for offline: the agent checks in only between tasks. */
	define('CSFM_HEARTBEAT_EVERY', 60);
}

/*
 * csfm_exec for a long step of the running task (a package install, a pfBlockerNG update): the same command,
 * environment and time limit, but every CSFM_HEARTBEAT_EVERY seconds the task's progress is reported
 * ("<step>, N min"), which also tells the server the firewall is alive.
 */
function csfm_exec_watched($cmd, $timeout, $step) {
	/* Done when the command itself exits, not when everything it started has: pfBlockerNG starts its services
	   (filterlog, DNSBL) on the way out, and they live on. So no /usr/bin/timeout wrapper, which waited for
	   them; the shell is replaced by the command ("exec"), and the time limit is kept here. */
	$full = 'exec ' . csfm_env_prefix() . $cmd . ' 2>&1';
	$proc = proc_open($full, array(1 => array('pipe', 'w')), $pipes);
	if (!is_resource($proc)) {
		return csfm_exec($cmd, $timeout);
	}
	stream_set_blocking($pipes[1], false);
	$out = '';
	$started = time();
	$last = $started;
	$rc = null;
	while (true) {
		$chunk = stream_get_contents($pipes[1]);
		if ($chunk !== false && $chunk !== '') {
			$out .= $chunk;
			if (strlen($out) > 200000) {
				$out = substr($out, -100000);
			}
		}
		$status = proc_get_status($proc);
		if (!$status['running']) {
			$rc = $status['exitcode'];
			$out .= (string)stream_get_contents($pipes[1]);
			break;
		}
		if (time() - $started > (int)$timeout) {
			proc_terminate($proc, 9);
			$out .= "\n[stopped by the agent after {$timeout} seconds]";
			$rc = 124;
			break;
		}
		if (time() - $last >= CSFM_HEARTBEAT_EVERY) {
			$last = time();
			csfm_task_heartbeat($step, $last - $started);
		}
		usleep(500000);
	}
	fclose($pipes[1]);  /* without waiting for services the command left running, which may hold the pipe */
	$close = proc_close($proc);
	if ($rc === null || $rc === -1) {
		$rc = $close;
	}
	return array((int)$rc, rtrim($out, "\n"));
}

/* The task being run now, for csfm_task_heartbeat: set by csfm_run_task. */
function csfm_task_context($ctx = null) {
	static $current = null;
	if (func_num_args() > 0) {
		$current = $ctx;
	}
	return $current;
}

/* Report the running task's current step; a failed report is not kept (the result that follows matters). */
function csfm_task_heartbeat($step, $elapsed) {
	$ctx = csfm_task_context();
	if (!$ctx) {
		return;
	}
	$text = $step . ($elapsed >= 60 ? sprintf(', %d min', intdiv($elapsed, 60)) : '');
	try {
		$ctx['client']->postJson("/tasks/{$ctx['id']}/result", array('status' => 'running', 'output' => $text,
		    'result' => array('progress' => array('step' => $text, 'percent' => null))));
	} catch (Exception $e) {
		csfm_log('Could not report progress of task ' . $ctx['id'] . ': ' . $e->getMessage(), LOG_WARNING);
	}
}

/*
 * Read config.xml again after another program (pkg, pfBlockerNG) or a rollback changed it on disk, so the
 * agent's next save keeps those changes. pfSense 2.7 and later (Plus 23.x and later) read it with
 * config_read_file(); older versions with parse_config(). Without this, the agent works on a stale copy.
 */
function csfm_config_reread() {
	@unlink('/tmp/config.cache');
	if (function_exists('config_read_file')) {
		config_read_file(false, true);
	} elseif (function_exists('parse_config')) {
		$GLOBALS['config'] = parse_config(true);
	}
}

function csfm_truncate($text, $limit = 60000) {
	return strlen($text) > $limit ? substr($text, -$limit) : $text;
}

/*
 * Whether pf accepts the ruleset pfSense generated: '' when it does, otherwise pf's error. pfSense keeps the
 * previous rules, or none after a boot, when its ruleset fails to load (a bad table file left by a removed
 * package, say), and then nothing is NATed: the firewall stays online while everything behind it is cut off.
 */
function csfm_rules_error() {
	if (!is_file(CSFM_RULES_DEBUG)) {
		return '';
	}
	$out = array();
	exec(escapeshellarg(CSFM_PFCTL) . ' -nf ' . escapeshellarg(CSFM_RULES_DEBUG) . ' 2>&1', $out, $rc);
	return $rc === 0 ? '' : csfm_truncate(trim(implode("\n", $out)) ?: "pfctl exit code {$rc}", 500);
}
