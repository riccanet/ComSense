<?php
/*
 * PfManager agent - task execution.
 *
 * The server can only ask for the task types below, and each one (except
 * read-only ones) needs the matching permission to be ticked locally in
 * Services > PfManager Agent. There is deliberately no "run a command" task.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');
require_once(__DIR__ . '/collect.inc');
require_once(__DIR__ . '/policies.inc');

define('PFM_UPGRADE_LOG', '/var/log/pfmanager-upgrade.log');

$pfm_task_capability = array(
	'backup' => 'backup',
	'apply_policy' => 'policy',
	'remove_policy' => 'policy',
	'check_updates' => null,
	'refresh_inventory' => null,
	'upgrade_system' => 'upgrade',
	'upgrade_packages' => 'upgrade',
	'install_package' => 'packages',
	'remove_package' => 'packages',
	'restart_service' => 'services',
	'restore_backup' => 'restore',
	'reboot' => 'reboot',
);

class PfmTaskDeferred extends Exception {
	/* Thrown by tasks that already reported their own result. */
}

function pfm_report_result($client, $taskId, $status, $output = '', $result = null) {
	$body = array('status' => $status, 'output' => pfm_truncate((string)$output));
	if ($result !== null) {
		$body['result'] = $result;
	}
	try {
		$client->postJson("/tasks/{$taskId}/result", $body);
	} catch (Exception $e) {
		/* Keep it and retry on the next cycle so results are never lost. */
		$state = pfm_state();
		$state['unsent_results'][(string)$taskId] = $body;
		pfm_save_state($state);
		pfm_log("Could not report result of task {$taskId}: " . $e->getMessage(), LOG_WARNING);
	}
}

function pfm_flush_unsent_results($client) {
	$state = pfm_state();
	foreach ($state['unsent_results'] ?? array() as $taskId => $body) {
		try {
			$client->postJson("/tasks/{$taskId}/result", $body);
			unset($state['unsent_results'][$taskId]);
		} catch (PfmHttpError $e) {
			if ($e->status === 404) {
				unset($state['unsent_results'][$taskId]);
			}
		}
	}
	pfm_save_state($state);
}

function pfm_run_task($client, $task) {
	global $pfm_task_capability;
	$id = (int)$task['id'];
	$type = (string)$task['type'];
	$payload = is_array($task['payload'] ?? null) ? $task['payload'] : array();

	if (!array_key_exists($type, $pfm_task_capability)) {
		pfm_report_result($client, $id, 'failed', "This agent does not support task type '{$type}'");
		return;
	}
	$cap = $pfm_task_capability[$type];
	if ($cap !== null && !pfm_has_capability($cap)) {
		pfm_report_result($client, $id, 'failed',
		    "Refused: '{$cap}' actions are not allowed in Services > PfManager Agent on this firewall.");
		pfm_log("Refused task {$id} ({$type}): capability {$cap} not granted", LOG_WARNING);
		return;
	}

	pfm_log("Running task {$id} ({$type})");
	try {
		$fn = 'pfm_task_' . $type;
		$res = $fn($client, $id, $payload);
		pfm_report_result($client, $id, 'success', $res['output'] ?? '', $res['result'] ?? null);
	} catch (PfmTaskDeferred $e) {
		return;
	} catch (Exception $e) {
		pfm_log("Task {$id} ({$type}) failed: " . $e->getMessage(), LOG_ERR);
		pfm_report_result($client, $id, 'failed', $e->getMessage());
	}
}

/* ----------------------------------------------------------------- handlers */

function pfm_upload_backup($client, $reason, $taskId = null) {
	$file = pfm_config_file();
	$xml = @file_get_contents($file);
	if ($xml === false || $xml === '') {
		throw new Exception("Cannot read {$file}");
	}
	$headers = array(
		'Content-Type: application/gzip',
		'X-PFM-SHA256: ' . hash('sha256', $xml),
		'X-PFM-Reason: ' . preg_replace('/[^a-z0-9_]/', '', $reason),
	);
	if ($taskId !== null) {
		$headers[] = 'X-PFM-Task-ID: ' . (int)$taskId;
	}
	$resp = $client->postRaw('/backups', gzencode($xml, 9), $headers);
	pfm_state_set('last_backup', array('sha256' => $resp['sha256'] ?? '', 'at' => gmdate('c')));
	return $resp;
}

function pfm_task_backup($client, $id, $payload) {
	$resp = pfm_upload_backup($client, $payload['reason'] ?? 'manual', $id);
	$note = !empty($resp['created']) ? 'Stored new backup' : 'Configuration unchanged since the last stored backup';
	return array('output' => "{$note} (#{$resp['backup_id']})", 'result' => $resp);
}

function pfm_task_check_updates($client, $id, $payload) {
	$info = pfm_check_updates(true);
	$msg = !empty($info['update_available'])
	    ? "Update available: {$info['installed_version']} -> {$info['version']}"
	    : "System is up to date ({$info['installed_version']})";
	$msg .= sprintf('; %d package update(s)', count($info['packages'] ?? array()));
	return array('output' => $msg, 'result' => $info);
}

function pfm_task_refresh_inventory($client, $id, $payload) {
	$state = pfm_state();
	unset($state['updates']);
	pfm_save_state($state);
	return array('output' => 'Full inventory is sent with every check-in; update cache cleared.');
}

function pfm_task_apply_policy($client, $id, $payload) {
	$policy = $payload['policy'] ?? null;
	if (!is_array($policy) || !isset($policy['id'], $policy['type'], $policy['content'], $policy['hash'])) {
		throw new Exception('Malformed policy payload');
	}
	return array('output' => pfm_apply_policy($policy));
}

function pfm_task_remove_policy($client, $id, $payload) {
	return array('output' => pfm_remove_policy((int)($payload['policy_id'] ?? 0)));
}

function pfm_valid_pkg($name) {
	return is_string($name) && preg_match('/^pfSense-pkg-[A-Za-z0-9_.+-]{1,64}$/', $name);
}

function pfm_task_install_package($client, $id, $payload) {
	$name = $payload['package'] ?? '';
	if (!pfm_valid_pkg($name)) {
		throw new Exception('Invalid package name');
	}
	list($rc, $out) = pfm_exec('/usr/local/sbin/pfSense-upgrade -y -i ' . escapeshellarg($name), 1800);
	if ($rc !== 0) {
		throw new Exception("pfSense-upgrade exited with {$rc}\n" . pfm_truncate($out));
	}
	return array('output' => pfm_truncate($out));
}

function pfm_task_remove_package($client, $id, $payload) {
	$name = $payload['package'] ?? '';
	if (!pfm_valid_pkg($name) || $name === 'pfSense-pkg-PfManager') {
		throw new Exception('Invalid package name');
	}
	list($rc, $out) = pfm_exec('/usr/local/sbin/pfSense-upgrade -y -r ' . escapeshellarg($name), 1800);
	if ($rc !== 0) {
		throw new Exception("pfSense-upgrade exited with {$rc}\n" . pfm_truncate($out));
	}
	return array('output' => pfm_truncate($out));
}

function pfm_task_upgrade_packages($client, $id, $payload) {
	$outdated = pfm_outdated_packages();
	if (!$outdated) {
		return array('output' => 'All packages are up to date');
	}
	$names = array_map(function ($p) { return escapeshellarg($p['name']); }, $outdated);
	list($rc, $out) = pfm_exec('/usr/sbin/pkg-static upgrade -y ' . implode(' ', $names), 3000);
	pfm_check_updates(true);
	if ($rc !== 0) {
		throw new Exception("pkg upgrade exited with {$rc}\n" . pfm_truncate($out));
	}
	return array('output' => pfm_truncate($out));
}

function pfm_task_restart_service($client, $id, $payload) {
	$name = (string)($payload['service'] ?? '');
	if (!function_exists('get_services') || !function_exists('service_control_restart')) {
		throw new Exception('Service control is not available');
	}
	foreach (get_services() as $svc) {
		if (($svc['name'] ?? '') === $name) {
			$msg = service_control_restart($name, $svc);
			sleep(2);
			$running = get_service_status($svc);
			if (!$running) {
				throw new Exception("{$name} did not start after restart. {$msg}");
			}
			return array('output' => trim("{$name} restarted. {$msg}"));
		}
	}
	throw new Exception("Unknown service '{$name}'");
}

function pfm_task_reboot($client, $id, $payload) {
	pfm_report_result($client, $id, 'success', 'Reboot started');
	pfm_log("Rebooting at the request of the management server (task {$id})", LOG_WARNING);
	mwexec_bg('/etc/rc.reboot');
	throw new PfmTaskDeferred();
}

function pfm_task_upgrade_system($client, $id, $payload) {
	pfm_state_set('inflight_upgrade', array(
		'task_id' => $id,
		'from_version' => pfm_product_version(),
		'started' => time(),
	));
	pfm_report_result($client, $id, 'running', 'Upgrade started; the firewall reboots when it finishes.');
	@unlink(PFM_UPGRADE_LOG);
	/* daemon(8) detaches fully, so the upgrade survives the agent cycle ending. */
	mwexec('/usr/sbin/daemon -f /bin/sh -c ' . escapeshellarg('/usr/local/sbin/pfSense-upgrade -y > ' . PFM_UPGRADE_LOG . ' 2>&1'));
	pfm_log("System upgrade started (task {$id})", LOG_WARNING);
	throw new PfmTaskDeferred();
}

/* Called at the start of each cycle to report on an upgrade that may have rebooted the box. */
function pfm_finish_inflight_upgrade($client) {
	$state = pfm_state();
	$up = $state['inflight_upgrade'] ?? null;
	if (!is_array($up)) {
		return;
	}
	exec('/bin/pgrep -f pfSense-upgrade', $pids, $rc);
	if ($rc === 0 && (time() - (int)$up['started']) < 4 * 3600) {
		return; /* still running */
	}
	$log = (string)@file_get_contents(PFM_UPGRADE_LOG);
	$now = pfm_product_version();
	if ($now !== $up['from_version']) {
		pfm_report_result($client, $up['task_id'], 'success', "Upgraded {$up['from_version']} -> {$now}\n" . pfm_truncate($log, 8000));
	} elseif (stripos($log, 'up to date') !== false || stripos($log, 'Your packages are up to date') !== false) {
		pfm_report_result($client, $up['task_id'], 'success', "Already up to date ({$now})\n" . pfm_truncate($log, 8000));
	} else {
		pfm_report_result($client, $up['task_id'], 'failed', "Version is still {$now}\n" . pfm_truncate($log, 8000));
	}
	$state = pfm_state();
	unset($state['inflight_upgrade'], $state['updates']);
	pfm_save_state($state);
}

function pfm_task_restore_backup($client, $id, $payload) {
	$backupId = (int)($payload['backup_id'] ?? 0);
	list($gz, $headers) = $client->download("/backups/{$backupId}");
	$xml = @gzdecode($gz);
	if ($xml === false) {
		throw new Exception('Downloaded backup is not valid gzip data');
	}
	$digest = hash('sha256', $xml);
	$expected = strtolower($headers['x-pfm-sha256'] ?? ($payload['sha256'] ?? ''));
	if ($expected === '' || !hash_equals($expected, $digest)) {
		throw new Exception('Checksum mismatch; restore aborted');
	}
	$prev = libxml_use_internal_errors(true);
	$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
	libxml_use_internal_errors($prev);
	if ($doc === false || $doc->getName() !== 'pfsense') {
		throw new Exception('Backup is not a valid pfSense configuration');
	}
	$tmp = PFM_DB_DIR . '/restore-config.xml';
	file_put_contents($tmp, $xml);
	chmod($tmp, 0600);

	pfm_snapshot_config();
	if (function_exists('config_install')) {
		$rc = config_install($tmp);
		if ($rc !== 0) {
			throw new Exception("config_install() failed with {$rc}");
		}
	} else {
		copy($tmp, pfm_config_file());
		@unlink('/tmp/config.cache');
	}
	@unlink($tmp);
	/*
	 * The restored config may predate some policy revisions. Forget the applied
	 * hashes (but keep what each policy owns) so the server re-applies them.
	 */
	$state = pfm_state();
	foreach ($state['policies'] as $pid => $p) {
		$state['policies'][$pid]['hash'] = '';
	}
	pfm_save_state($state);

	pfm_report_result($client, $id, 'success', "Restored backup #{$backupId} ({$digest}); rebooting");
	pfm_log("Configuration restored from backup {$backupId}; rebooting", LOG_WARNING);
	mwexec_bg('/etc/rc.reboot');
	throw new PfmTaskDeferred();
}
