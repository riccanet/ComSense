<?php
/*
 * ComSense agent - task execution.
 *
 * The server can only ask for the task types below, and each one (except
 * read-only ones) needs the matching permission to be ticked locally in
 * Services > ComSense Agent. There is no "run a command" task; the remote
 * terminal (terminal.inc) is a separate opt-in, approved per session.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');
require_once(__DIR__ . '/collect.inc');
require_once(__DIR__ . '/policies.inc');
require_once(__DIR__ . '/guard.inc');
require_once(__DIR__ . '/terminal.inc');

define('CSFM_UPGRADE_LOG', '/var/log/comsense-upgrade.log');

$csfm_task_capability = array(
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
	'update_agent' => 'upgrade',
	'open_terminal' => 'shell',
);

/* Tasks that change the configuration and run under the change guard (guard.inc). */
$csfm_guarded_tasks = array('apply_policy', 'remove_policy');

class CsfmTaskDeferred extends Exception {
	/* Thrown by tasks that already reported their own result. */
}

function csfm_report_result($client, $taskId, $status, $output = '', $result = null) {
	$body = array('status' => $status, 'output' => csfm_truncate((string)$output));
	if ($result !== null) {
		$body['result'] = $result;
	}
	try {
		$client->postJson("/tasks/{$taskId}/result", $body);
	} catch (Exception $e) {
		/* Keep it and retry on the next cycle so results are never lost. */
		$state = csfm_state();
		$state['unsent_results'][(string)$taskId] = $body;
		csfm_save_state($state);
		csfm_log("Could not report result of task {$taskId}: " . $e->getMessage(), LOG_WARNING);
	}
}

function csfm_flush_unsent_results($client) {
	$state = csfm_state();
	foreach ($state['unsent_results'] ?? array() as $taskId => $body) {
		try {
			$client->postJson("/tasks/{$taskId}/result", $body);
			unset($state['unsent_results'][$taskId]);
		} catch (CsfmHttpError $e) {
			if ($e->status === 404) {
				unset($state['unsent_results'][$taskId]);
			}
		}
	}
	csfm_save_state($state);
}

function csfm_run_task($client, $task) {
	global $csfm_task_capability;
	$id = (int)$task['id'];
	$type = (string)$task['type'];
	$payload = is_array($task['payload'] ?? null) ? $task['payload'] : array();

	if (!array_key_exists($type, $csfm_task_capability)) {
		csfm_report_result($client, $id, 'failed', "This agent does not support task type '{$type}'");
		return;
	}
	$cap = $csfm_task_capability[$type];
	if ($cap !== null && !csfm_has_capability($cap)) {
		csfm_report_result($client, $id, 'failed',
		    "Refused: '{$cap}' actions are not allowed in Services > ComSense Agent on this firewall.");
		csfm_log("Refused task {$id} ({$type}): capability {$cap} not granted", LOG_WARNING);
		return;
	}

	global $csfm_guarded_tasks, $csfm_rolled_back;
	$guarded = in_array($type, $csfm_guarded_tasks, true);
	if ($guarded && !empty($csfm_rolled_back)) {
		csfm_report_result($client, $id, 'failed', 'Not run: an earlier change in this check-in was rolled back.');
		return;
	}

	csfm_log("Running task {$id} ({$type})");
	try {
		if ($guarded) {
			csfm_guard_begin($id, csfm_task_label($type, $payload));
		}
		$fn = 'csfm_task_' . $type;
		$res = $fn($client, $id, $payload);
		if ($guarded && !csfm_verify_connectivity()) {
			$csfm_rolled_back = csfm_guard_rollback('the management server was unreachable right after the change');
			csfm_report_result($client, $id, 'failed', 'Rolled back: the firewall could not reach the management '
			    . 'server after this change, so the previous configuration was restored.');
			return;
		}
		csfm_report_result($client, $id, 'success', $res['output'] ?? '', $res['result'] ?? null);
	} catch (CsfmTaskDeferred $e) {
		return;
	} catch (Exception $e) {
		csfm_log("Task {$id} ({$type}) failed: " . $e->getMessage(), LOG_ERR);
		$msg = $e->getMessage();
		/* A half-applied change can still cut the firewall off. */
		if ($guarded && !csfm_server_reachable(2)) {
			$csfm_rolled_back = csfm_guard_rollback('the management server was unreachable after a failed change');
			$msg .= "\nRolled back: the previous configuration was restored.";
		}
		csfm_report_result($client, $id, 'failed', $msg);
	}
}

function csfm_task_label($type, $payload) {
	if ($type === 'apply_policy') {
		$p = $payload['policy'] ?? array();
		$rev = isset($p['revision']) ? " revision {$p['revision']}" : '';
		return "apply policy '" . ($p['name'] ?? ($p['id'] ?? '?')) . "'{$rev}";
	}
	if ($type === 'remove_policy') {
		return 'remove policy #' . (int)($payload['policy_id'] ?? 0);
	}
	if ($type === 'restore_backup') {
		return 'restore backup #' . (int)($payload['backup_id'] ?? 0);
	}
	if ($type === 'open_terminal') {
		return 'open a remote terminal';
	}
	if ($type === 'update_agent') {
		return 'update agent to ' . ($payload['version'] ?? '?');
	}
	return $type;
}

/* ----------------------------------------------------------------- handlers */

function csfm_upload_backup($client, $reason, $taskId = null) {
	$file = csfm_config_file();
	$xml = @file_get_contents($file);
	if ($xml === false || $xml === '') {
		throw new Exception("Cannot read {$file}");
	}
	$headers = array(
		'Content-Type: application/gzip',
		'X-CSFM-SHA256: ' . hash('sha256', $xml),
		'X-CSFM-Reason: ' . preg_replace('/[^a-z0-9_]/', '', $reason),
	);
	if ($taskId !== null) {
		$headers[] = 'X-CSFM-Task-ID: ' . (int)$taskId;
	}
	$resp = $client->postRaw('/backups', gzencode($xml, 9), $headers);
	csfm_state_set('last_backup', array('sha256' => $resp['sha256'] ?? '', 'at' => gmdate('c')));
	return $resp;
}

function csfm_task_backup($client, $id, $payload) {
	$resp = csfm_upload_backup($client, $payload['reason'] ?? 'manual', $id);
	$note = !empty($resp['created']) ? 'Stored new backup' : 'Configuration unchanged since the last stored backup';
	return array('output' => "{$note} (#{$resp['backup_id']})", 'result' => $resp);
}

function csfm_task_check_updates($client, $id, $payload) {
	/* Asked for by an operator, so it runs now (bounded by the cycle's own time limit). */
	$info = csfm_check_updates();
	$msg = !empty($info['update_available'])
	    ? "Update available: {$info['installed_version']} -> {$info['version']}"
	    : "System is up to date ({$info['installed_version']})";
	$msg .= sprintf('; %d package update(s)', count($info['packages'] ?? array()));
	return array('output' => $msg, 'result' => $info);
}

function csfm_task_refresh_inventory($client, $id, $payload) {
	csfm_forget_updates();
	csfm_schedule_update_check(true);
	return array('output' => 'Full inventory is sent with every check-in; update check restarted.');
}

function csfm_task_apply_policy($client, $id, $payload) {
	$policy = $payload['policy'] ?? null;
	if (!is_array($policy) || !isset($policy['id'], $policy['type'], $policy['content'], $policy['hash'])) {
		throw new Exception('Malformed policy payload');
	}
	return array('output' => csfm_apply_policy($policy));
}

function csfm_task_remove_policy($client, $id, $payload) {
	return array('output' => csfm_remove_policy((int)($payload['policy_id'] ?? 0)));
}

function csfm_valid_pkg($name) {
	return is_string($name) && preg_match('/^pfSense-pkg-[A-Za-z0-9_.+-]{1,64}$/', $name);
}

function csfm_task_install_package($client, $id, $payload) {
	$name = $payload['package'] ?? '';
	if (!csfm_valid_pkg($name)) {
		throw new Exception('Invalid package name');
	}
	list($rc, $out) = csfm_exec('/usr/local/sbin/pfSense-upgrade -y -i ' . escapeshellarg($name), 1800);
	if ($rc !== 0) {
		throw new Exception("pfSense-upgrade exited with {$rc}\n" . csfm_truncate($out));
	}
	return array('output' => csfm_truncate($out));
}

function csfm_task_remove_package($client, $id, $payload) {
	$name = $payload['package'] ?? '';
	if (!csfm_valid_pkg($name) || $name === 'pfSense-pkg-ComSense') {
		throw new Exception('Invalid package name');
	}
	list($rc, $out) = csfm_exec('/usr/local/sbin/pfSense-upgrade -y -r ' . escapeshellarg($name), 1800);
	if ($rc !== 0) {
		throw new Exception("pfSense-upgrade exited with {$rc}\n" . csfm_truncate($out));
	}
	return array('output' => csfm_truncate($out));
}

function csfm_task_upgrade_packages($client, $id, $payload) {
	$outdated = csfm_outdated_packages();
	if (!$outdated) {
		return array('output' => 'All packages are up to date');
	}
	$names = array_map(function ($p) { return escapeshellarg($p['name']); }, $outdated);
	list($rc, $out) = csfm_exec(CSFM_PKG . ' upgrade -y ' . implode(' ', $names), 3000);
	csfm_schedule_update_check(true);
	if ($rc !== 0) {
		throw new Exception("pkg upgrade exited with {$rc}\n" . csfm_truncate($out));
	}
	return array('output' => csfm_truncate($out));
}

function csfm_task_restart_service($client, $id, $payload) {
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

function csfm_task_reboot($client, $id, $payload) {
	csfm_report_result($client, $id, 'success', 'Reboot started');
	csfm_log("Rebooting at the request of the management server (task {$id})", LOG_WARNING);
	mwexec_bg('/etc/rc.reboot');
	throw new CsfmTaskDeferred();
}

function csfm_task_upgrade_system($client, $id, $payload) {
	csfm_state_set('inflight_upgrade', array(
		'task_id' => $id,
		'from_version' => csfm_product_version(),
		'started' => time(),
	));
	csfm_report_result($client, $id, 'running', 'Upgrade started; the firewall reboots when it finishes.');
	@unlink(CSFM_UPGRADE_LOG);
	/* daemon(8) detaches fully, so the upgrade survives the agent cycle ending. */
	mwexec('/usr/sbin/daemon -f /bin/sh -c ' . escapeshellarg('/usr/local/sbin/pfSense-upgrade -y > ' . CSFM_UPGRADE_LOG . ' 2>&1'));
	csfm_log("System upgrade started (task {$id})", LOG_WARNING);
	throw new CsfmTaskDeferred();
}

/* Called at the start of each cycle to report on an upgrade that may have rebooted the box. */
function csfm_finish_inflight_upgrade($client) {
	$state = csfm_state();
	$up = $state['inflight_upgrade'] ?? null;
	if (!is_array($up)) {
		return;
	}
	exec('/bin/pgrep -f pfSense-upgrade', $pids, $rc);
	if ($rc === 0 && (time() - (int)$up['started']) < 4 * 3600) {
		return; /* still running */
	}
	$log = (string)@file_get_contents(CSFM_UPGRADE_LOG);
	$now = csfm_product_version();
	if ($now !== $up['from_version']) {
		csfm_report_result($client, $up['task_id'], 'success', "Upgraded {$up['from_version']} -> {$now}\n" . csfm_truncate($log, 8000));
	} elseif (stripos($log, 'up to date') !== false || stripos($log, 'Your packages are up to date') !== false) {
		csfm_report_result($client, $up['task_id'], 'success', "Already up to date ({$now})\n" . csfm_truncate($log, 8000));
	} else {
		csfm_report_result($client, $up['task_id'], 'failed', "Version is still {$now}\n" . csfm_truncate($log, 8000));
	}
	$state = csfm_state();
	unset($state['inflight_upgrade']);
	csfm_save_state($state);
	csfm_forget_updates();
	csfm_schedule_update_check(true);
}

/* ------------------------------------------------------------ agent update */

define('CSFM_AGENT_UPDATE_PKG', CSFM_DB_DIR . '/agent-update.pkg');
define('CSFM_AGENT_UPDATE_LOG', CSFM_DB_DIR . '/agent-update.log');

/*
 * Install a newer agent package from the management server. The package comes
 * over the authenticated, pinned API and must match the SHA-256 in the task.
 * pkg runs in a detached process (it replaces these files and the agent is
 * restarted afterwards); the next cycle reports the outcome.
 */
function csfm_task_update_agent($client, $id, $payload) {
	$version = (string)($payload['version'] ?? '');
	$file = (string)($payload['file'] ?? '');
	$sha = strtolower((string)($payload['sha256'] ?? ''));
	if (!preg_match('/^\d+(\.\d+)*([._-][0-9A-Za-z]+)*$/', $version) || $file !== "pfSense-pkg-ComSense-{$version}.pkg"
	    || !preg_match('/^[0-9a-f]{64}$/', $sha)) {
		throw new Exception('Malformed agent update task');
	}
	if (version_compare($version, CSFM_AGENT_VERSION, '<=')) {
		return array('output' => 'The agent is already at ' . CSFM_AGENT_VERSION);
	}
	list($data) = $client->download('/agent-package/' . rawurlencode($file), 300);
	if (!hash_equals($sha, hash('sha256', (string)$data))) {
		throw new Exception('Checksum mismatch; update aborted');
	}
	csfm_ensure_db_dir();
	file_put_contents(CSFM_AGENT_UPDATE_PKG, $data);
	chmod(CSFM_AGENT_UPDATE_PKG, 0600);
	@unlink(CSFM_AGENT_UPDATE_LOG);
	csfm_state_set('inflight_agent_update', array(
		'task_id' => $id, 'from' => CSFM_AGENT_VERSION, 'to' => $version, 'started' => time(),
	));
	csfm_report_result($client, $id, 'running', "Downloaded {$file} (sha256 verified); installing.");
	$log = escapeshellarg(CSFM_AGENT_UPDATE_LOG);
	$cmd = 'sleep 2; ' . CSFM_PKG . ' add ' . escapeshellarg(CSFM_AGENT_UPDATE_PKG) . " > {$log} 2>&1; "
	    . "/usr/local/etc/rc.d/comsense.sh restart >> {$log} 2>&1";
	/* daemon(8) detaches fully: the install survives the agent restart it triggers. */
	mwexec('/usr/sbin/daemon -f /bin/sh -c ' . escapeshellarg($cmd));
	csfm_log("Agent update to {$version} started (task {$id})", LOG_NOTICE);
	throw new CsfmTaskDeferred();
}

/* At the start of each cycle: report an agent update started earlier. */
function csfm_finish_agent_update($client) {
	$up = csfm_state()['inflight_agent_update'] ?? null;
	if (!is_array($up)) {
		return;
	}
	$log = csfm_truncate((string)@file_get_contents(CSFM_AGENT_UPDATE_LOG), 6000);
	if (CSFM_AGENT_VERSION === $up['to']) {
		csfm_report_result($client, $up['task_id'], 'success', "Agent updated {$up['from']} -> {$up['to']}\n" . $log);
	} else {
		exec('/bin/pgrep -f ' . escapeshellarg('agent-update.pkg'), $pids, $rc);
		if ($rc === 0 && time() - (int)$up['started'] < 1800) {
			return; /* still installing */
		}
		csfm_report_result($client, $up['task_id'], 'failed',
		    "The agent is still at " . CSFM_AGENT_VERSION . " after installing {$up['to']}.\n" . $log);
	}
	$state = csfm_state();
	unset($state['inflight_agent_update']);
	csfm_save_state($state);
	@unlink(CSFM_AGENT_UPDATE_PKG);
}

/* ------------------------------------------------------- remote terminal */

/* Leave a request for comsense-agentd, which starts the terminal helper after this cycle. */
function csfm_task_open_terminal($client, $id, $payload) {
	$sid = (string)($payload['session'] ?? '');
	if (!preg_match(CSFM_TERM_SID_RE, $sid)) {
		throw new Exception('Malformed terminal task');
	}
	csfm_ensure_db_dir();
	@mkdir(CSFM_TERM_DIR, 0700, true);
	file_put_contents(csfm_terminal_request_file($sid), (string)time());
	csfm_log('Remote terminal ' . substr($sid, 0, 8) . ' requested by the management server', LOG_NOTICE);
	return array('output' => 'Terminal requested; the firewall connects to the console in a moment.');
}

function csfm_task_restore_backup($client, $id, $payload) {
	$backupId = (int)($payload['backup_id'] ?? 0);
	list($gz, $headers) = $client->download("/backups/{$backupId}");
	$xml = @gzdecode($gz);
	if ($xml === false) {
		throw new Exception('Downloaded backup is not valid gzip data');
	}
	$digest = hash('sha256', $xml);
	$expected = strtolower($headers['x-csfm-sha256'] ?? ($payload['sha256'] ?? ''));
	if ($expected === '' || !hash_equals($expected, $digest)) {
		throw new Exception('Checksum mismatch; restore aborted');
	}
	$prev = libxml_use_internal_errors(true);
	$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);
	libxml_use_internal_errors($prev);
	if ($doc === false || $doc->getName() !== 'pfsense') {
		throw new Exception('Backup is not a valid pfSense configuration');
	}
	if (!isset($doc->installedpackages->comsense)) {
		throw new Exception('This backup does not contain the ComSense agent settings; restoring it would '
		    . 'disconnect the firewall from ComSense, so it was not restored.');
	}
	$tmp = CSFM_DB_DIR . '/restore-config.xml';
	file_put_contents($tmp, $xml);
	chmod($tmp, 0600);

	/* If the firewall cannot reach the server after the reboot, the watchdog restores the current config. */
	csfm_guard_begin($id, csfm_task_label('restore_backup', $payload), 'reboot');
	if (function_exists('config_install')) {
		$rc = config_install($tmp);
		if ($rc !== 0) {
			throw new Exception("config_install() failed with {$rc}");
		}
	} else {
		copy($tmp, csfm_config_file());
		@unlink('/tmp/config.cache');
	}
	@unlink($tmp);
	/*
	 * The restored config may predate some policy revisions. Forget the applied
	 * hashes (but keep what each policy owns) so the server re-applies them.
	 */
	$state = csfm_state();
	foreach ($state['policies'] as $pid => $p) {
		$state['policies'][$pid]['hash'] = '';
	}
	csfm_save_state($state);

	csfm_report_result($client, $id, 'success', "Restored backup #{$backupId} ({$digest}); rebooting");
	csfm_log("Configuration restored from backup {$backupId}; rebooting", LOG_WARNING);
	mwexec_bg('/etc/rc.reboot');
	throw new CsfmTaskDeferred();
}
