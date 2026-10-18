<?php
/*
 * ComSense agent - enrollment and the check-in cycle.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');
require_once(__DIR__ . '/collect.inc');
require_once(__DIR__ . '/tasks.inc');
require_once(__DIR__ . '/guard.inc');

/*
 * Exchange a one-time enrollment key for a device token. The key itself is
 * never stored on the firewall after this succeeds.
 */
function csfm_enroll($settings, $key) {
	$client = new CsfmClient($settings);
	$resp = $client->postJson('/enroll', array(
		'enrollment_key' => trim($key),
		'agent_version' => CSFM_AGENT_VERSION,
		'system' => csfm_collect_system(),
		'capabilities' => csfm_capabilities($settings),
	));
	if (empty($resp['token']) || empty($resp['device_id'])) {
		throw new CsfmHttpError('Server did not return device credentials');
	}
	csfm_save_credentials(array(
		'device_id' => $resp['device_id'],
		'token' => $resp['token'],
		'server_url' => csfm_normalize_url($settings['server_url']),
		'enrolled_at' => gmdate('c'),
	));
	$state = csfm_state();
	$state['device_status'] = $resp['status'] ?? '';
	unset($state['last_error'], $state['auth_failed']);
	csfm_save_state($state);
	if (!empty($resp['checkin_interval'])) {
		csfm_write_interval((int)$resp['checkin_interval']);
	}
	csfm_log("Enrolled with {$settings['server_url']} as device {$resp['device_id']}");
	return $resp;
}

function csfm_write_interval($seconds) {
	csfm_ensure_db_dir();
	$seconds = max(15, min(3600, (int)$seconds));
	file_put_contents(CSFM_INTERVAL_FILE, (string)$seconds);
}

function csfm_record_error($message) {
	$state = csfm_state();
	$state['last_error'] = array('message' => $message, 'at' => gmdate('c'));
	csfm_save_state($state);
	csfm_log($message, LOG_ERR);
}

/*
 * Rules and port forwards can reference aliases, so they must go before the
 * aliases they use are removed, and aliases must exist before they are loaded.
 */
function csfm_order_tasks($tasks) {
	$state = csfm_state();
	$rank = function ($t) use ($state) {
		$p = $t['payload'] ?? array();
		if ($t['type'] === 'remove_policy') {
			$type = $state['policies'][(string)($p['policy_id'] ?? '')]['type'] ?? '';
			return in_array($type, array('firewall_rules', 'port_forward'), true) ? 0 : 1;
		}
		if ($t['type'] === 'apply_policy') {
			$type = $p['policy']['type'] ?? '';
			return $type === 'aliases' ? 2 : (in_array($type, array('firewall_rules', 'port_forward'), true) ? 4 : 3);
		}
		return 5;
	};
	$indexed = array();
	foreach (array_values($tasks) as $i => $t) {
		$indexed[] = array($rank($t), $i, $t);
	}
	usort($indexed, function ($a, $b) {
		return ($a[0] <=> $b[0]) ?: ($a[1] <=> $b[1]);
	});
	return array_map(function ($x) { return $x[2]; }, $indexed);
}

/* One full agent cycle. Returns a short human-readable outcome. */
function csfm_cycle() {
	$settings = csfm_settings();
	if (empty($settings['enable'])) {
		return 'Agent is disabled';
	}
	if (!csfm_is_enrolled()) {
		if (empty($settings['enrollment_key'])) {
			return 'Not enrolled: enter an enrollment key in Services > ComSense Agent';
		}
		try {
			$key = csfm_apply_enrollment_code($settings, $settings['enrollment_key']);
			csfm_enroll($settings, $key);
			/* Keep the URL and pin that came with the code; drop the key. */
			$settings['enrollment_key'] = '';
			csfm_cfg_set(CSFM_CONFIG_PATH, $settings);
			write_config('ComSense: enrollment complete, key removed');
		} catch (Exception $e) {
			csfm_record_error('Enrollment failed: ' . $e->getMessage());
			return 'Enrollment failed';
		}
	}

	/* Normally the watchdog does this; covers a watchdog that is not running. */
	$guard = csfm_guard();
	if ($guard !== null && time() > (int)$guard['deadline']) {
		csfm_guard_watchdog();
	}

	$client = csfm_client();
	csfm_flush_unsent_results($client);
	csfm_finish_inflight_upgrade($client);
	csfm_finish_agent_update($client);

	try {
		$report = csfm_collect_report();
		$resp = $client->postJson('/checkin', $report);
	} catch (CsfmHttpError $e) {
		if ($e->status === 401) {
			csfm_state_set('auth_failed', true);
			csfm_record_error('The server no longer recognises this firewall. Enter a new enrollment key to re-enroll.');
		} else {
			csfm_record_error('Check-in failed: ' . $e->getMessage());
		}
		return 'Check-in failed';
	}

	csfm_guard_checkin_ok();
	$state = csfm_state();
	$state['last_checkin'] = gmdate('c');
	/* The server has the rollback reports now. */
	$sent = array_map(function ($r) { return $r['id']; }, $report['rollbacks'] ?? array());
	$state['rollbacks'] = array_values(array_filter($state['rollbacks'] ?? array(), function ($r) use ($sent) {
		return !in_array($r['id'], $sent, true);
	}));
	$state['device_status'] = $resp['status'] ?? '';
	unset($state['last_error'], $state['auth_failed']);
	csfm_save_state($state);
	if (!empty($resp['checkin_interval'])) {
		csfm_write_interval((int)$resp['checkin_interval']);
	}

	if (!empty($resp['rotate_token'])) {
		try {
			$new = $client->postJson('/token/rotate', new stdClass());
			$creds = csfm_credentials();
			$creds['token'] = $new['token'];
			$creds['rotated_at'] = gmdate('c');
			csfm_save_credentials($creds);
			$client->setToken($new['token']);
			csfm_log('Device token rotated');
		} catch (Exception $e) {
			csfm_log('Token rotation failed: ' . $e->getMessage(), LOG_WARNING);
		}
	}

	if (($resp['status'] ?? '') === 'pending') {
		return 'Waiting for approval on the management server';
	}

	if (!empty($resp['upload_backup']) && csfm_has_capability('backup')) {
		try {
			csfm_upload_backup($client, 'config_change');
		} catch (Exception $e) {
			csfm_log('Automatic backup failed: ' . $e->getMessage(), LOG_WARNING);
		}
	}

	$tasks = is_array($resp['tasks'] ?? null) ? $resp['tasks'] : array();
	foreach (csfm_order_tasks($tasks) as $task) {
		csfm_run_task($client, $task);
	}
	/* After checking in, so a slow or unreachable update repository never delays it. */
	csfm_schedule_update_check();
	return sprintf('Checked in; ran %d task(s)', count($tasks));
}

/*
 * Between check-ins: wait up to $seconds for the server to say there is work
 * (a queued task, e.g. "Check now" in the console). The firewall still only
 * connects out; the server holds each request for up to 55 seconds.
 * Returns 'wake', 'idle' (the time passed) or 'error'.
 */
function csfm_wait_for_work($seconds) {
	$settings = csfm_settings();
	if (empty($settings['enable']) || !csfm_is_enrolled()) {
		return 'error';
	}
	$end = time() + max(1, (int)$seconds);
	try {
		$client = csfm_client();
		while (($left = $end - time()) > 0) {
			$chunk = min(55, $left);
			$resp = $client->getJson('/wait?timeout=' . $chunk, $chunk + 15);
			if (!empty($resp['wake'])) {
				return 'wake';
			}
		}
	} catch (Exception $e) {
		return 'error';
	}
	return 'idle';
}
