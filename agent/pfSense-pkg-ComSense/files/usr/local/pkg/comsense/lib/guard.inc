<?php
/*
 * ComSense agent - change guard (automatic rollback).
 *
 * Before a task changes the configuration, the agent keeps a copy of the
 * last known-good config.xml and of its own state. The change then has to
 * prove that the firewall can still reach the management server:
 *
 *   1. right after it is applied (csfm_verify_connectivity), and
 *   2. again when its probation window ends. The watchdog
 *      (comsense-watchdogd, "agent.php watchdog") checks this every 30
 *      seconds in its own process, so it also works if a cycle hangs or the
 *      change needed a reboot (restores).
 *
 * A successful check-in after the change confirms it early. If the server
 * cannot be reached at either point, the copy is put back, the services are
 * reloaded (or the firewall rebooted, for restores) and the rollback is
 * reported to the server on the next check-in. Any HTTP answer from the
 * server counts as reachable; only connection-level failures (DNS, routing,
 * filtering, TLS) trigger a rollback.
 *
 * The guard lives next to config.xml so it survives a reboot even with RAM
 * disks for /var. Several changes in a row share one guard and one copy:
 * a rollback returns to the configuration from before the first of them.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');
require_once(__DIR__ . '/collect.inc');

if (!defined('CSFM_GUARD_DIR')) {
	define('CSFM_GUARD_DIR', '/cf/conf/comsense');
}
if (!defined('CSFM_GUARD_WINDOW')) {
	/* Seconds a change stays on probation. Restores add the reboot time. */
	define('CSFM_GUARD_WINDOW', 300);
}
if (!defined('CSFM_GUARD_REBOOT_WINDOW')) {
	define('CSFM_GUARD_REBOOT_WINDOW', 900);
}
if (!defined('CSFM_GUARD_CONFIRM_AFTER')) {
	/* A check-in this long after the last change confirms it before the window ends. */
	define('CSFM_GUARD_CONFIRM_AFTER', 60);
}
if (!defined('CSFM_VERIFY_DELAY')) {
	define('CSFM_VERIFY_DELAY', 3);
}
if (!defined('CSFM_RETRY_DELAY')) {
	define('CSFM_RETRY_DELAY', 5);
}
define('CSFM_GUARD_FILE', CSFM_GUARD_DIR . '/guard.json');
define('CSFM_GUARD_CONFIG', CSFM_GUARD_DIR . '/known-good-config.xml');
define('CSFM_GUARD_STATE', CSFM_GUARD_DIR . '/known-good-state.json');

function csfm_guard() {
	$g = @json_decode((string)@file_get_contents(CSFM_GUARD_FILE), true);
	return is_array($g) ? $g : null;
}

function csfm_guard_save($guard) {
	$tmp = CSFM_GUARD_FILE . '.tmp';
	file_put_contents($tmp, json_encode($guard, JSON_UNESCAPED_SLASHES));
	chmod($tmp, 0600);
	rename($tmp, CSFM_GUARD_FILE);
}

/* Serialise guard changes between the agent cycle and the watchdog. */
function csfm_guard_locked($fn) {
	if (!is_dir(CSFM_GUARD_DIR)) {
		mkdir(CSFM_GUARD_DIR, 0700, true);
	}
	$fh = fopen(CSFM_GUARD_DIR . '/.lock', 'c');
	flock($fh, LOCK_EX);
	try {
		return $fn();
	} finally {
		flock($fh, LOCK_UN);
		fclose($fh);
	}
}

/*
 * Start (or extend) probation for a change made by task $taskId.
 * $mode: 'reload' puts the config back and reloads services; 'reboot' also reboots.
 */
function csfm_guard_begin($taskId, $label, $mode = 'reload') {
	return csfm_guard_locked(function () use ($taskId, $label, $mode) {
		$guard = csfm_guard();
		if ($guard === null) {
			if (!@copy(csfm_config_file(), CSFM_GUARD_CONFIG)) {
				throw new Exception('Could not keep a copy of the configuration; change not applied');
			}
			chmod(CSFM_GUARD_CONFIG, 0600);
			file_put_contents(CSFM_GUARD_STATE, json_encode(csfm_state()));
			chmod(CSFM_GUARD_STATE, 0600);
			$guard = array('id' => bin2hex(random_bytes(8)), 'started' => time(), 'tasks' => array(), 'mode' => 'reload');
		}
		$window = $mode === 'reboot' ? CSFM_GUARD_REBOOT_WINDOW : CSFM_GUARD_WINDOW;
		$guard['tasks'][] = array('id' => (int)$taskId, 'label' => (string)$label);
		if ($mode === 'reboot') {
			$guard['mode'] = 'reboot';
		}
		$guard['changed'] = time();
		$guard['deadline'] = max((int)($guard['deadline'] ?? 0), time() + $window);
		csfm_guard_save($guard);
		return $guard;
	});
}

function csfm_guard_clear() {
	@unlink(CSFM_GUARD_FILE);
	@unlink(CSFM_GUARD_CONFIG);
	@unlink(CSFM_GUARD_STATE);
}

/* The change worked: forget the copy. */
function csfm_guard_confirm($why) {
	csfm_guard_locked(function () use ($why) {
		$guard = csfm_guard();
		if ($guard === null) {
			return;
		}
		csfm_guard_clear();
		$ids = implode(', ', array_map(function ($t) { return $t['id']; }, $guard['tasks']));
		csfm_log("Change confirmed ({$why}); rollback copy discarded (tasks {$ids})");
	});
}

/* After a successful check-in: confirm once the change has had time to show problems. */
function csfm_guard_checkin_ok() {
	$guard = csfm_guard();
	if ($guard !== null && time() - (int)($guard['changed'] ?? 0) >= CSFM_GUARD_CONFIRM_AFTER) {
		csfm_guard_confirm('check-in succeeded');
	}
}

/* True if the management server answers at all (any HTTP status). */
function csfm_server_reachable($attempts = 3, $delay = CSFM_RETRY_DELAY) {
	try {
		$client = csfm_client();
	} catch (Exception $e) {
		return true; /* not enrolled or not configured: nothing to protect */
	}
	for ($i = 0; $i < $attempts; $i++) {
		if ($i > 0 && $delay > 0) {
			sleep($delay);
		}
		try {
			$client->getJson('/ping', 10);
			return true;
		} catch (CsfmHttpError $e) {
			if ($e->status > 0) {
				return true;
			}
			csfm_log('Connectivity check failed: ' . $e->getMessage(), LOG_WARNING);
		} catch (Exception $e) {
			csfm_log('Connectivity check failed: ' . $e->getMessage(), LOG_WARNING);
		}
	}
	return false;
}

/* Right after a change: wait for reloads to settle, then check. */
function csfm_verify_connectivity() {
	if (CSFM_VERIFY_DELAY > 0) {
		sleep(CSFM_VERIFY_DELAY);
	}
	return csfm_server_reachable(4);
}

/*
 * Put the known-good configuration back. Returns the rollback record, or
 * null if there was nothing to roll back.
 */
function csfm_guard_rollback($reason) {
	return csfm_guard_locked(function () use ($reason) {
		$guard = csfm_guard();
		if ($guard === null || !is_readable(CSFM_GUARD_CONFIG)) {
			csfm_guard_clear();
			return null;
		}
		$labels = implode('; ', array_map(function ($t) { return $t['label']; }, $guard['tasks']));
		csfm_log("Rolling back configuration ({$reason}): {$labels}", LOG_ERR);

		copy(CSFM_GUARD_CONFIG, csfm_config_file());
		@unlink('/tmp/config.cache');
		if (function_exists('parse_config')) {
			$GLOBALS['config'] = parse_config(true);
		}
		$known = @json_decode((string)@file_get_contents(CSFM_GUARD_STATE), true);
		$state = csfm_state();
		if (is_array($known)) {
			/* Policies go back to what they were; keep fresher bookkeeping. */
			$state['policies'] = $known['policies'] ?? array();
		}
		$record = array(
			'id' => $guard['id'],
			'tasks' => array_map(function ($t) { return $t['id']; }, $guard['tasks']),
			'changes' => $labels,
			'reason' => $reason,
			'changed_at' => gmdate('c', (int)($guard['started'] ?? time())),
			'rolled_back_at' => gmdate('c'),
		);
		$state['rollbacks'][] = $record;
		$state['last_rollback'] = $record;
		csfm_save_state($state);
		csfm_guard_clear();

		if (function_exists('write_config')) {
			write_config('ComSense: rolled back changes after losing contact with the management server');
		}
		if (($guard['mode'] ?? '') === 'reboot') {
			csfm_log('Rebooting to finish the rollback', LOG_ERR);
			mwexec_bg('/etc/rc.reboot');
		} else {
			/* Reapply interfaces, routing, filter and services from the restored config. */
			mwexec('/etc/rc.reload_all');
		}
		return $record;
	});
}

/* Watchdog pass: roll back an unconfirmed change once its window has passed. */
function csfm_guard_watchdog() {
	$guard = csfm_guard();
	if ($guard === null) {
		return 'No change on probation';
	}
	$left = (int)$guard['deadline'] - time();
	if ($left > 0) {
		return "Change on probation for {$left} more second(s)";
	}
	if (csfm_server_reachable(3)) {
		csfm_guard_confirm('server reachable when the probation window ended');
		return 'Change confirmed';
	}
	csfm_guard_rollback('the management server was unreachable when the probation window ended');
	return 'Change rolled back';
}
