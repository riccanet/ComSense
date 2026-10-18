<?php
/*
 * PfManager agent - enrollment and the check-in cycle.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');
require_once(__DIR__ . '/collect.inc');
require_once(__DIR__ . '/tasks.inc');

/*
 * Exchange a one-time enrollment key for a device token. The key itself is
 * never stored on the firewall after this succeeds.
 */
function pfm_enroll($settings, $key) {
	$client = new PfmClient($settings);
	$resp = $client->postJson('/enroll', array(
		'enrollment_key' => trim($key),
		'agent_version' => PFM_AGENT_VERSION,
		'system' => pfm_collect_system(),
		'capabilities' => pfm_capabilities($settings),
	));
	if (empty($resp['token']) || empty($resp['device_id'])) {
		throw new PfmHttpError('Server did not return device credentials');
	}
	pfm_save_credentials(array(
		'device_id' => $resp['device_id'],
		'token' => $resp['token'],
		'server_url' => pfm_normalize_url($settings['server_url']),
		'enrolled_at' => gmdate('c'),
	));
	$state = pfm_state();
	$state['device_status'] = $resp['status'] ?? '';
	unset($state['last_error'], $state['auth_failed']);
	pfm_save_state($state);
	if (!empty($resp['checkin_interval'])) {
		pfm_write_interval((int)$resp['checkin_interval']);
	}
	pfm_log("Enrolled with {$settings['server_url']} as device {$resp['device_id']}");
	return $resp;
}

function pfm_clear_enrollment_key() {
	$settings = pfm_settings();
	if (!empty($settings['enrollment_key'])) {
		$settings['enrollment_key'] = '';
		pfm_cfg_set(PFM_CONFIG_PATH, $settings);
		write_config('PfManager: enrollment complete, key removed');
	}
}

function pfm_write_interval($seconds) {
	pfm_ensure_db_dir();
	$seconds = max(15, min(3600, (int)$seconds));
	file_put_contents(PFM_INTERVAL_FILE, (string)$seconds);
}

function pfm_record_error($message) {
	$state = pfm_state();
	$state['last_error'] = array('message' => $message, 'at' => gmdate('c'));
	pfm_save_state($state);
	pfm_log($message, LOG_ERR);
}

/*
 * Rules can reference aliases, so rules must go before the aliases they use
 * are removed, and aliases must exist before rules that use them are loaded.
 */
function pfm_order_tasks($tasks) {
	$state = pfm_state();
	$rank = function ($t) use ($state) {
		$p = $t['payload'] ?? array();
		if ($t['type'] === 'remove_policy') {
			$type = $state['policies'][(string)($p['policy_id'] ?? '')]['type'] ?? '';
			return $type === 'firewall_rules' ? 0 : 1;
		}
		if ($t['type'] === 'apply_policy') {
			$type = $p['policy']['type'] ?? '';
			return $type === 'aliases' ? 2 : ($type === 'firewall_rules' ? 4 : 3);
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
function pfm_cycle() {
	$settings = pfm_settings();
	if (empty($settings['enable'])) {
		return 'Agent is disabled';
	}
	if (!pfm_is_enrolled()) {
		if (empty($settings['enrollment_key'])) {
			return 'Not enrolled: enter an enrollment key in Services > PfManager Agent';
		}
		try {
			pfm_enroll($settings, $settings['enrollment_key']);
			pfm_clear_enrollment_key();
		} catch (Exception $e) {
			pfm_record_error('Enrollment failed: ' . $e->getMessage());
			return 'Enrollment failed';
		}
	}

	$client = pfm_client();
	pfm_flush_unsent_results($client);
	pfm_finish_inflight_upgrade($client);

	try {
		$resp = $client->postJson('/checkin', pfm_collect_report());
	} catch (PfmHttpError $e) {
		if ($e->status === 401) {
			pfm_state_set('auth_failed', true);
			pfm_record_error('The server no longer recognises this firewall. Enter a new enrollment key to re-enroll.');
		} else {
			pfm_record_error('Check-in failed: ' . $e->getMessage());
		}
		return 'Check-in failed';
	}

	$state = pfm_state();
	$state['last_checkin'] = gmdate('c');
	$state['device_status'] = $resp['status'] ?? '';
	unset($state['last_error'], $state['auth_failed']);
	pfm_save_state($state);
	if (!empty($resp['checkin_interval'])) {
		pfm_write_interval((int)$resp['checkin_interval']);
	}

	if (!empty($resp['rotate_token'])) {
		try {
			$new = $client->postJson('/token/rotate', new stdClass());
			$creds = pfm_credentials();
			$creds['token'] = $new['token'];
			$creds['rotated_at'] = gmdate('c');
			pfm_save_credentials($creds);
			$client->setToken($new['token']);
			pfm_log('Device token rotated');
		} catch (Exception $e) {
			pfm_log('Token rotation failed: ' . $e->getMessage(), LOG_WARNING);
		}
	}

	if (($resp['status'] ?? '') === 'pending') {
		return 'Waiting for approval on the management server';
	}

	if (!empty($resp['upload_backup']) && pfm_has_capability('backup')) {
		try {
			pfm_upload_backup($client, 'config_change');
		} catch (Exception $e) {
			pfm_log('Automatic backup failed: ' . $e->getMessage(), LOG_WARNING);
		}
	}

	$tasks = is_array($resp['tasks'] ?? null) ? $resp['tasks'] : array();
	foreach (pfm_order_tasks($tasks) as $task) {
		pfm_run_task($client, $task);
	}
	return sprintf('Checked in; ran %d task(s)', count($tasks));
}
