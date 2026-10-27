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

if (!defined('CSFM_UPGRADE_LOG')) {
	define('CSFM_UPGRADE_LOG', '/var/log/comsense-upgrade.log');
}
if (!defined('CSFM_PFSENSE_UPGRADE_LOG')) {
	define('CSFM_PFSENSE_UPGRADE_LOG', '/cf/conf/upgrade_log.txt');
}

$csfm_task_capability = array(
	'backup' => 'backup',
	'apply_policy' => 'policy',
	'remove_policy' => 'policy',
	'check_updates' => null,
	'refresh_inventory' => null,
	'read_logs' => null,
	'upgrade_system' => 'upgrade',
	'upgrade_packages' => 'upgrade',
	'install_package' => 'packages',
	'remove_package' => 'packages',
	'restart_service' => 'services',
	'restore_backup' => 'restore',
	'reboot' => 'reboot',
	'update_agent' => 'upgrade',
	'open_terminal' => 'shell',
	'nat_add' => 'policy',
	'nat_remove' => 'policy',
	'nat_edit' => 'policy',
	'alias_add' => 'policy',
	'alias_edit' => 'policy',
	'alias_remove' => 'policy',
	'ddns_add' => 'policy',
	'ddns_edit' => 'policy',
	'ddns_remove' => 'policy',
	'update_branch' => 'upgrade',
	'free_disk_space' => 'upgrade',
	'be_destroy' => 'upgrade',
	'notifications' => 'policy',
);

/* Tasks that change the configuration and run under the change guard (guard.inc). */
$csfm_guarded_tasks = array('apply_policy', 'remove_policy', 'nat_add', 'nat_remove', 'nat_edit',
	'alias_add', 'alias_edit', 'alias_remove', 'ddns_add', 'ddns_edit', 'ddns_remove');

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
	if ($type === 'nat_add') {
		return 'add port forward ' . ($payload['rule']['descr'] ?? '');
	}
	if ($type === 'nat_remove') {
		return 'remove port forward ' . ($payload['descr'] ?? '');
	}
	if ($type === 'alias_add' || $type === 'alias_edit') {
		return ($type === 'alias_add' ? 'add' : 'change') . ' alias ' . ($payload['alias']['name'] ?? '');
	}
	if ($type === 'alias_remove') {
		return 'remove alias ' . ($payload['name'] ?? '');
	}
	if ($type === 'ddns_add' || $type === 'ddns_edit') {
		return ($type === 'ddns_add' ? 'add' : 'change') . ' dynamic DNS ' . ($payload['entry']['host'] ?? '');
	}
	if ($type === 'ddns_remove') {
		return 'remove dynamic DNS ' . ($payload['descr'] ?? '');
	}
	if ($type === 'update_branch') {
		return 'switch the update branch to ' . ($payload['branch'] ?? '?');
	}
	if ($type === 'nat_edit') {
		return 'change port forward ' . ($payload['rule']['descr'] ?? '');
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
	/* Asked for by an operator, so it runs now (bounded by the cycle's own time limit), after any
	 * metadata refresh pfSense is running: the operator may just have switched branch. */
	$info = csfm_check_updates(true);
	$msg = !empty($info['update_available'])
	    ? "Update available: {$info['installed_version']} -> {$info['version']}"
	    : "System is up to date ({$info['installed_version']})";
	$msg .= sprintf('; %d package update(s)', count($info['packages'] ?? array()));
	if (!empty($info['error'])) {
		$msg .= "\n" . $info['error'];
	} elseif (!empty($info['upgrade_message'])) {
		$msg .= "\npfSense-upgrade: " . $info['upgrade_message'];
	}
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

/*
 * Free space an upgrade needs on the root filesystem: pfSense's own upgrade downloads the new release and
 * (on ZFS) keeps a snapshot of the old system while it replaces it; a disk that fills up halfway leaves
 * the firewall half-upgraded. Short of it, the package download cache is cleared first.
 */
if (!defined('CSFM_UPGRADE_MIN_FREE')) {
	define('CSFM_UPGRADE_MIN_FREE', 2 * 1024 * 1024 * 1024);
}
if (!defined('CSFM_PACKAGES_MIN_FREE')) {
	define('CSFM_PACKAGES_MIN_FREE', 512 * 1024 * 1024);
}

function csfm_bytes($n) {
	return $n >= 1073741824 ? sprintf('%.1f GB', $n / 1073741824) : sprintf('%d MB', $n / 1048576);
}

function csfm_require_free_space($needed, $what) {
	$free = @disk_free_space('/');
	if ($free === false || $free >= $needed) {
		return '';
	}
	csfm_exec(CSFM_PKG . ' clean -ay', 300);
	$after = @disk_free_space('/');
	if ($after !== false && $after >= $needed) {
		return sprintf('Cleared the package cache first (%s free now)', csfm_bytes($after));
	}
	throw new Exception(sprintf('%s not started: only %s free on the firewall, %s needed. Free space first: '
	    . 'run "Free disk space" from its page, and remove old boot environments (its Configuration page, '
	    . 'Boot environments).', $what, csfm_bytes($after === false ? $free : $after), csfm_bytes($needed)));
}

/*
 * Upload config.xml before an upgrade starts; the server keeps it (pinned) to roll back to. The
 * server also queues a backup ahead of every upgrade; this covers one queued without it. No backup,
 * no upgrade.
 */
function csfm_backup_before_upgrade($client, $id) {
	try {
		$resp = csfm_upload_backup($client, 'pre_upgrade', $id);
	} catch (Exception $e) {
		throw new Exception('Upgrade not started: the configuration could not be backed up first (' . $e->getMessage() . ')');
	}
	return 'Configuration backed up before the upgrade (#' . ($resp['backup_id'] ?? '?') . ')';
}

function csfm_task_upgrade_packages($client, $id, $payload) {
	$outdated = csfm_outdated_packages();
	if (!$outdated) {
		return array('output' => 'All packages are up to date');
	}
	$space = csfm_require_free_space(CSFM_PACKAGES_MIN_FREE, 'Package upgrade');
	$backed_up = trim($space . "\n" . csfm_backup_before_upgrade($client, $id));
	$names = array_map(function ($p) { return escapeshellarg($p['name']); }, $outdated);
	list($rc, $out) = csfm_exec(CSFM_PKG . ' upgrade -y ' . implode(' ', $names), 3000);
	csfm_schedule_update_check(true);
	if ($rc !== 0) {
		throw new Exception("pkg upgrade exited with {$rc}\n" . csfm_truncate($out));
	}
	return array('output' => $backed_up . "\n" . csfm_truncate($out));
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
	$space = csfm_require_free_space(CSFM_UPGRADE_MIN_FREE, 'Upgrade');
	$backed_up = trim($space . "\n" . csfm_backup_before_upgrade($client, $id));
	$detached = csfm_detach_package_interfaces();
	if (csfm_interface_mismatch()) {
		csfm_reattach_package_interfaces(true);
		throw new Exception('Upgrade not started: an assigned interface does not exist on the firewall, so the new '
		    . "version's first boot would stop at the console's interface mismatch prompt. Fix the assignments "
		    . 'in Interfaces > Assignments first.');
	}
	if ($detached) {
		$backed_up .= "\nUnassigned for the upgrade (pfSense removes the packages that create them; ComSense "
		    . 'assigns them again, with their settings, once they exist again): ' . implode(', ', $detached);
	}
	csfm_state_set('inflight_upgrade', array(
		'task_id' => $id,
		'from_version' => csfm_product_version(),
		'started' => time(),
	));
	$progress = array('percent' => 3, 'step' => 'Starting the upgrade');
	csfm_report_result($client, $id, 'running', $backed_up . "\nUpgrade started; the firewall reboots when it finishes.",
	    array('progress' => $progress));
	csfm_state_set('inflight_upgrade', array_merge(csfm_state()['inflight_upgrade'], array('progress' => $progress)));
	@unlink(CSFM_UPGRADE_LOG);
	/* daemon(8) detaches fully, so the upgrade survives the agent cycle ending. */
	mwexec(csfm_env_prefix() . '/usr/sbin/daemon -f /bin/sh -c ' . escapeshellarg('/usr/local/sbin/pfSense-upgrade -y > ' . CSFM_UPGRADE_LOG . ' 2>&1'));
	csfm_log("System upgrade started (task {$id})", LOG_WARNING);
	throw new CsfmTaskDeferred();
}

/*
 * The upgrade's log: ours (pfSense-upgrade's output), or pfSense's own upgrade log when that is newer
 * (a major upgrade carries on after its first reboot, logging there).
 */
function csfm_upgrade_log($up) {
	$best = CSFM_UPGRADE_LOG;
	$own = @filemtime(CSFM_UPGRADE_LOG) ?: 0;
	$pf = @filemtime(CSFM_PFSENSE_UPGRADE_LOG) ?: 0;
	if ($pf > $own && $pf >= (int)($up['started'] ?? 0)) {
		$best = CSFM_PFSENSE_UPGRADE_LOG;
	}
	return (string)@file_get_contents($best);
}

/*
 * How far a pfSense upgrade got, from pfSense-upgrade's log: {percent, step}. The steps are its
 * ">>>" lines; while it downloads or installs, its "[n/m]" counters move the percentage on.
 */
function csfm_upgrade_progress($log) {
	$steps = array(
		// marker in the log (lower case) => (percent, step, percent the step's [n/m] counter runs up to)
		'updating repositories metadata' => array(8, 'Updating repository information', 0),
		'downloading upgrade packages' => array(15, 'Downloading packages', 35),
		'upgrading pfsense-boot' => array(38, 'Upgrading the boot loader', 0),
		'upgrading pfsense kernel' => array(42, 'Upgrading the kernel', 0),
		'upgrading pfsense-kernel' => array(42, 'Upgrading the kernel', 0),
		'upgrading necessary packages' => array(50, 'Installing packages', 88),
		'upgrading pfsense-base' => array(50, 'Installing the base system', 0),
		'rebooting' => array(92, 'Rebooting', 0),
		'reboot' => array(92, 'Rebooting', 0),
	);
	$lower = strtolower($log);
	$best = null;
	$at = -1;
	foreach ($steps as $marker => $step) {
		$pos = strrpos($lower, $marker);
		if ($pos !== false && $pos > $at) {
			$at = $pos;
			$best = $step;
		}
	}
	if ($best === null) {
		return array('percent' => 5, 'step' => 'Starting the upgrade');
	}
	list($percent, $name, $upto) = $best;
	if ($upto > $percent && preg_match_all('/\[(\d+)\/(\d+)\]/', substr($log, $at), $m, PREG_SET_ORDER)) {
		$last = end($m);
		$done = (int)$last[1];
		$total = max(1, (int)$last[2]);
		$percent = $percent + (int)floor(($upto - $percent) * min($done, $total) / $total);
		$name .= " ({$done} of {$total})";
	}
	return array('percent' => $percent, 'step' => $name);
}

/* Called at the start of each cycle to report on an upgrade that may have rebooted the box. */
function csfm_finish_inflight_upgrade($client) {
	$state = csfm_state();
	$up = $state['inflight_upgrade'] ?? null;
	if (!is_array($up)) {
		return;
	}
	/* [p]: never matches the shell running pgrep itself. */
	exec("/bin/pgrep -f '[p]fSense-upgrade'", $pids, $rc);
	$log = csfm_upgrade_log($up);
	if ($rc === 0 && (time() - (int)$up['started']) < 4 * 3600) {
		/* Still running: report how far it got when that changes (the firewall's page shows it). */
		$progress = csfm_upgrade_progress($log);
		if ($progress !== ($up['progress'] ?? null)) {
			$tail = implode("\n", array_slice(explode("\n", trim($log)), -15));
			csfm_report_result($client, $up['task_id'], 'running', "{$progress['step']} ({$progress['percent']}%)\n\n{$tail}",
			    array('progress' => $progress));
			$up['progress'] = $progress;
			csfm_state_set('inflight_upgrade', $up);
		}
		return;
	}
	$now = csfm_product_version();
	if ($now !== $up['from_version']) {
		csfm_report_result($client, $up['task_id'], 'success', "Upgraded {$up['from_version']} -> {$now}\n" . csfm_truncate($log, 8000));
	} elseif (stripos($log, 'up to date') !== false) {
		/* Not a success: the upgrade was queued because a newer version was reported, and none was installed. */
		csfm_report_result($client, $up['task_id'], 'failed', "Not upgraded: pfSense found no newer version to install "
		    . "(still {$now}). Run Check for updates and check the update branch.\n" . csfm_truncate($log, 8000));
	} else {
		csfm_report_result($client, $up['task_id'], 'failed', "Not upgraded: the version is still {$now}. If the "
		    . "firewall rebooted, the new version did not finish its first boot (see the console).\n" . csfm_truncate($log, 8000));
	}
	$state = csfm_state();
	unset($state['inflight_upgrade']);
	csfm_save_state($state);
	csfm_forget_updates();
	csfm_schedule_update_check(true);
}

/* ------------------------------------------------ package interfaces across upgrades */

/*
 * Interfaces created by add-on packages: NetBird (wt0), Tailscale, ZeroTier. A pfSense upgrade removes packages
 * that are not in Netgate's repository, so on the new version's first boot the interface is gone, and pfSense
 * stops at the console's "interface mismatch" prompt until someone reassigns the interfaces by hand. Before an
 * upgrade the agent unassigns them, keeping their settings (rules and other references keep their optN name),
 * and assigns them again, as they were, once the interface exists again: right after an upgrade that did not
 * happen, or once the package is reinstalled on the new version.
 */
if (!defined('CSFM_PACKAGE_IF_RE')) {
	define('CSFM_PACKAGE_IF_RE', '/^(wt|tailscale|zt)[0-9a-z]*$/');
}

function csfm_interface_exists($ifname) {
	if (function_exists('does_interface_exist')) {
		return (bool)does_interface_exist($ifname);
	}
	exec('/sbin/ifconfig ' . escapeshellarg($ifname) . ' >/dev/null 2>&1', $out, $rc);
	return $rc === 0;
}

/* pfSense's own boot-time check, on the configuration as it is now (no-op where it is not available). */
function csfm_interface_mismatch() {
	return function_exists('is_interface_mismatch') && is_interface_mismatch();
}

/* Unassign package interfaces; returns "DESCR (if)" for each. Their settings are kept in the agent's state. */
function csfm_detach_package_interfaces() {
	$detached = csfm_state()['detached_interfaces'] ?? array();
	$names = array();
	foreach ((array)csfm_cfg_get('interfaces', array()) as $key => $iface) {
		if ($key === 'wan' || $key === 'lan' || !is_array($iface)
		    || !preg_match(CSFM_PACKAGE_IF_RE, (string)($iface['if'] ?? ''))) {
			continue;
		}
		$detached[$key] = $iface;
		$names[] = ($iface['descr'] ?? strtoupper($key)) . " ({$iface['if']})";
	}
	if (!$names) {
		return array();
	}
	/* Saved before the configuration changes, so the settings are never lost. */
	csfm_state_set('detached_interfaces', $detached);
	foreach (array_keys($detached) as $key) {
		csfm_cfg_del("interfaces/{$key}");
	}
	write_config('ComSense: unassigned ' . implode(', ', $names) . ' for the upgrade');
	csfm_log('Unassigned for the upgrade: ' . implode(', ', $names), LOG_WARNING);
	return $names;
}

/*
 * Assign interfaces unassigned for an upgrade again, each once it exists (or all, $force, when an upgrade did
 * not start). Called every cycle; nothing happens while an upgrade runs. Returns "DESCR (if)" for each.
 */
function csfm_reattach_package_interfaces($force = false) {
	$state = csfm_state();
	$detached = $state['detached_interfaces'] ?? array();
	if (!$detached || (!$force && isset($state['inflight_upgrade']))) {
		return array();
	}
	$done = array();
	foreach ($detached as $key => $iface) {
		$name = ($iface['descr'] ?? strtoupper($key)) . " ({$iface['if']})";
		$taken = csfm_cfg_get("interfaces/{$key}");
		if (is_array($taken)) {
			/* Assigned again by hand (or the slot reused): leave it as it is. */
			csfm_log("Not re-assigning {$name}: {$key} is assigned to " . ($taken['if'] ?? '?') . ' now', LOG_WARNING);
			unset($detached[$key]);
			continue;
		}
		if (!$force && !csfm_interface_exists((string)$iface['if'])) {
			continue;
		}
		csfm_cfg_set("interfaces/{$key}", $iface);
		unset($detached[$key]);
		$done[$key] = $name;
	}
	$state = csfm_state();
	if ($detached) {
		$state['detached_interfaces'] = $detached;
	} else {
		unset($state['detached_interfaces']);
	}
	csfm_save_state($state);
	if ($done) {
		write_config('ComSense: assigned ' . implode(', ', $done) . ' again after the upgrade');
		if (function_exists('interface_configure')) {
			foreach (array_keys($done) as $key) {
				interface_configure($key, true);
			}
		}
		if (function_exists('filter_configure')) {
			filter_configure();
		}
		csfm_log('Assigned again after the upgrade: ' . implode(', ', $done), LOG_WARNING);
	}
	return array_values($done);
}

/* For the check-in: interfaces waiting to be assigned again, as {key, descr, if}. */
function csfm_detached_interfaces_report() {
	$out = array();
	foreach (csfm_state()['detached_interfaces'] ?? array() as $key => $iface) {
		$out[] = array('key' => (string)$key, 'descr' => (string)($iface['descr'] ?? ''), 'if' => (string)($iface['if'] ?? ''));
	}
	return $out;
}

/* ------------------------------------------------------------ disk space */

/*
 * Free space without touching anything the firewall runs on: pkg's download cache and rotated, compressed
 * logs. Boot environments (ZFS) are only listed: which one to remove is the operator's call.
 */
function csfm_task_free_disk_space($client, $id, $payload) {
	$before = @disk_free_space('/');
	list($rc, $out) = csfm_exec(CSFM_PKG . ' clean -ay', 300);
	$removed = 0;
	foreach (array_merge((array)glob('/var/log/*.bz2'), (array)glob('/var/log/*.gz'), (array)glob('/var/log/*/*.bz2'),
	    (array)glob('/var/log/*/*.gz')) as $f) {
		if (is_file($f) && @unlink($f)) {
			$removed++;
		}
	}
	$after = @disk_free_space('/');
	$lines = array(sprintf('Free space: %s -> %s (package cache cleared; %d rotated log file(s) removed)',
	    $before === false ? '?' : csfm_bytes($before), $after === false ? '?' : csfm_bytes($after), $removed));
	if ($rc !== 0) {
		$lines[] = 'pkg clean: ' . csfm_truncate(trim($out), 500);
	}
	if (is_executable(CSFM_BECTL)) {
		list($brc, $bes) = csfm_exec(CSFM_BECTL . ' list', 30);
		if ($brc === 0 && trim($bes) !== '') {
			$lines[] = "\nBoot environments (old ones can be removed from the firewall's Configuration page in "
			    . "ComSense; never the one marked N or R):\n" . trim($bes);
		}
	}
	return array('output' => implode("\n", $lines),
	    'result' => array('free_before' => csfm_byte_count($before), 'free_after' => csfm_byte_count($after)));
}

/*
 * Remove one boot environment and its snapshot (bectl destroy -o) to free space. Never the one running
 * now or the one the next boot uses: those are checked here, on the firewall, whatever the server sent.
 */
function csfm_task_be_destroy($client, $id, $payload) {
	$name = (string)($payload['name'] ?? '');
	if (!preg_match('/^[A-Za-z0-9._:+-]{1,128}$/', $name)) {
		throw new Exception('Invalid boot environment name');
	}
	$found = null;
	foreach (csfm_boot_environments() as $be) {
		if ($be['name'] === $name) {
			$found = $be;
		}
	}
	if ($found === null) {
		throw new Exception("No boot environment '{$name}' on this firewall");
	}
	if ($found['active'] || $found['next_boot']) {
		throw new Exception("'{$name}' is the boot environment " . ($found['active'] ? 'running now' : 'used at the next boot')
		    . '; it cannot be removed');
	}
	$before = @disk_free_space('/');
	list($rc, $out) = csfm_exec(CSFM_BECTL . ' destroy -o ' . escapeshellarg($name), 600);
	if ($rc !== 0) {
		throw new Exception("bectl destroy exited with {$rc}\n" . csfm_truncate(trim($out), 2000));
	}
	$after = @disk_free_space('/');
	$msg = "Removed boot environment {$name} ({$found['space']})";
	if ($before !== false && $after !== false) {
		$msg .= sprintf('; free space %s -> %s', csfm_bytes($before), csfm_bytes($after));
	}
	return array('output' => $msg, 'result' => array('boot_environments' => csfm_boot_environments()));
}

/* ------------------------------------------------------------------ logs */

if (!defined('CSFM_LOG_DIR')) {
	define('CSFM_LOG_DIR', '/var/log');
}
/* The logs the console can show (Status > System Logs), by name. */
$csfm_logs = array(
	'system' => 'system.log',
	'firewall' => 'filter.log',
	'dhcp' => 'dhcpd.log',
	'resolver' => 'resolver.log',
	'gateways' => 'gateways.log',
	'openvpn' => 'openvpn.log',
	'ipsec' => 'ipsec.log',
	'auth' => 'auth.log',
	'ntp' => 'ntpd.log',
	'routing' => 'routing.log',
);
define('CSFM_LOG_MAX_LINES', 2000);
define('CSFM_LOG_SCAN_LINES', 200000);
define('CSFM_LOG_MAX_BYTES', 1000000);

/*
 * The last lines of one log, optionally only those containing a text (case-insensitive). The search
 * covers the whole current log file (up to its last CSFM_LOG_SCAN_LINES lines), not just what is
 * returned. Read-only; nothing leaves the firewall but the lines asked for.
 */
function csfm_task_read_logs($client, $id, $payload) {
	global $csfm_logs;
	$name = (string)($payload['log'] ?? 'system');
	if (!isset($csfm_logs[$name])) {
		throw new Exception("Unknown log '{$name}'");
	}
	$lines = max(1, min(CSFM_LOG_MAX_LINES, (int)($payload['lines'] ?? 200)));
	$search = substr((string)($payload['search'] ?? ''), 0, 200);
	$file = CSFM_LOG_DIR . '/' . $csfm_logs[$name];
	if (!is_readable($file)) {
		return array('output' => "{$csfm_logs[$name]} does not exist on this firewall",
		    'result' => array('log' => $name, 'lines' => array(), 'matched' => 0, 'scanned' => 0));
	}
	/* tail(1) reads the end of a large file without loading all of it. */
	list($rc, $out) = csfm_exec('/usr/bin/tail -n ' . ($search === '' ? $lines : CSFM_LOG_SCAN_LINES) . ' '
	    . escapeshellarg($file), 60);
	$all = $out === '' ? array() : explode("\n", rtrim($out, "\n"));
	$scanned = count($all);
	if ($search !== '') {
		$all = array_values(array_filter($all, function ($l) use ($search) { return stripos($l, $search) !== false; }));
	}
	$matched = count($all);
	$keep = array_map(function ($l) { return substr($l, 0, 2000); }, array_slice($all, -$lines));
	/* The newest lines that fit in about 1 MB (the server takes results up to 2 MB of JSON). */
	$size = 0;
	for ($i = count($keep) - 1; $i >= 0; $i--) {
		$size += strlen($keep[$i]) + 8;
		if ($size > CSFM_LOG_MAX_BYTES) {
			$keep = array_slice($keep, $i + 1);
			break;
		}
	}
	return array(
		'output' => sprintf('%s: %d line(s)%s', $csfm_logs[$name], count($keep),
		    $search !== '' ? sprintf(' of %d containing "%s" in the last %d', $matched, $search, $scanned) : ''),
		'result' => array('log' => $name, 'lines' => $keep, 'matched' => $matched, 'scanned' => $scanned,
		    'search' => $search),
	);
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
	/*
	 * -f: pkg up to 2.1 (every pfSense release so far) refuses `pkg add` for a package that is already
	 * installed, whatever the version ("the most recent version of ... is already installed"). Forced, it
	 * installs over the old one and runs the new package's install script, not the old one's removal.
	 */
	$cmd = 'sleep 2; ' . CSFM_PKG . ' add -f ' . escapeshellarg(CSFM_AGENT_UPDATE_PKG) . " > {$log} 2>&1; "
	    . 'touch ' . escapeshellarg(CSFM_DB_DIR . '/checkin-now') . '; '
	    . "/usr/local/etc/rc.d/comsense.sh restart >> {$log} 2>&1";
	/* daemon(8) detaches fully: the install survives the agent restart it triggers. */
	mwexec(csfm_env_prefix() . '/usr/sbin/daemon -f /bin/sh -c ' . escapeshellarg($cmd));
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

/* ------------------------------------------- single changes from the firewall's page */

function csfm_task_nat_add($client, $id, $payload) {
	$r = $payload['rule'] ?? null;
	if (!is_array($r) || empty($r['target']) || empty($r['destination']['port'])) {
		throw new Exception('Malformed port forward');
	}
	return array('output' => csfm_add_port_forward($r));
}

function csfm_task_nat_remove($client, $id, $payload) {
	$fp = (string)($payload['fingerprint'] ?? '');
	if (!preg_match('/^[0-9a-f]{16}$/', $fp)) {
		throw new Exception('Malformed port forward reference');
	}
	return array('output' => csfm_remove_port_forward($fp));
}

function csfm_task_nat_edit($client, $id, $payload) {
	$fp = (string)($payload['fingerprint'] ?? '');
	$r = $payload['rule'] ?? null;
	if (!preg_match('/^[0-9a-f]{16}$/', $fp) || !is_array($r) || empty($r['target']) || empty($r['destination']['port'])) {
		throw new Exception('Malformed port forward change');
	}
	return array('output' => csfm_edit_port_forward($fp, $r));
}

function csfm_alias_payload($payload) {
	$a = $payload['alias'] ?? null;
	if (!is_array($a) || !is_string($a['name'] ?? null) || !is_string($a['type'] ?? null)
	    || !is_array($a['address'] ?? null) || !$a['address']) {
		throw new Exception('Malformed alias');
	}
	return $a;
}

function csfm_task_alias_add($client, $id, $payload) {
	return array('output' => csfm_add_alias(csfm_alias_payload($payload)));
}

function csfm_task_alias_edit($client, $id, $payload) {
	return array('output' => csfm_edit_alias(csfm_alias_payload($payload)));
}

function csfm_task_alias_remove($client, $id, $payload) {
	return array('output' => csfm_remove_alias((string)($payload['name'] ?? '')));
}

function csfm_ddns_payload($payload) {
	$r = $payload['entry'] ?? null;
	if (!is_array($r) || !preg_match('/^[a-z0-9._-]{1,32}$/i', (string)($r['type'] ?? ''))
	    || (string)($r['interface'] ?? '') === '') {
		throw new Exception('Malformed dynamic DNS entry');
	}
	return $r;
}

function csfm_ddns_reference($payload) {
	$fp = (string)($payload['fingerprint'] ?? '');
	if (!preg_match('/^[0-9a-f]{16}$/', $fp)) {
		throw new Exception('Malformed dynamic DNS reference');
	}
	return $fp;
}

function csfm_task_ddns_add($client, $id, $payload) {
	return array('output' => csfm_add_ddns(csfm_ddns_payload($payload)));
}

function csfm_task_ddns_edit($client, $id, $payload) {
	return array('output' => csfm_edit_ddns(csfm_ddns_reference($payload), csfm_ddns_payload($payload)));
}

function csfm_task_ddns_remove($client, $id, $payload) {
	return array('output' => csfm_remove_ddns(csfm_ddns_reference($payload)));
}

/* System > Update > Update Settings > Branch, as pfSense's own page saves it. */
function csfm_task_update_branch($client, $id, $payload) {
	$name = (string)($payload['branch'] ?? '');
	foreach (csfm_update_branches() as $repo) {
		if ((string)($repo['name'] ?? '') !== $name) {
			continue;
		}
		csfm_cfg_set('system/pkg_repo_conf_path', (string)$repo['path']);
		write_config("ComSense: update branch set to {$name}");
		if (function_exists('pkg_switch_repo')) {
			pkg_switch_repo((string)$repo['path']);
		}
		csfm_forget_updates();
		csfm_schedule_update_check(true, true);
		return array('output' => 'Update branch set to ' . ($repo['descr'] ?? $name) . '; checking for updates on it '
		    . '(the result appears in a few minutes)');
	}
	throw new Exception("This firewall does not offer the update branch '{$name}'");
}

function csfm_task_notifications($client, $id, $payload) {
	if (!isset($payload['smtp']) || !is_bool($payload['smtp'])) {
		throw new Exception('Malformed notification setting');
	}
	return array('output' => csfm_set_smtp_notifications($payload['smtp']));
}

/*
 * A restored backup keeps the firewall's current ComSense settings (installedpackages/comsense): the
 * permissions its owner allows now (shell, restore, policies...), not the ones the backup had.
 */
function csfm_keep_local_settings($xml) {
	$current = @file_get_contents(csfm_config_file());
	if ($current === false || !class_exists('DOMDocument')) {
		return $xml;
	}
	$restored = new DOMDocument();
	$live = new DOMDocument();
	if (!@$restored->loadXML($xml, LIBXML_NONET) || !@$live->loadXML($current, LIBXML_NONET)) {
		return $xml;
	}
	$mine = (new DOMXPath($live))->query('/pfsense/installedpackages/comsense')->item(0);
	$theirs = (new DOMXPath($restored))->query('/pfsense/installedpackages/comsense')->item(0);
	if ($mine === null || $theirs === null) {
		return $xml;
	}
	$theirs->parentNode->replaceChild($restored->importNode($mine, true), $theirs);
	return $restored->saveXML();
}

/* A config.xml element as pfSense's config array: text for leaves, arrays for children (repeated tags as lists). */
function csfm_dom_to_array($el) {
	$out = array();
	$hasChildren = false;
	foreach ($el->childNodes as $child) {
		if ($child->nodeType !== XML_ELEMENT_NODE) {
			continue;
		}
		$hasChildren = true;
		$value = csfm_dom_to_array($child);
		if (array_key_exists($child->nodeName, $out)) {
			if (!is_array($out[$child->nodeName]) || !array_key_exists(0, $out[$child->nodeName])) {
				$out[$child->nodeName] = array($out[$child->nodeName]);
			}
			$out[$child->nodeName][] = $value;
		} else {
			$out[$child->nodeName] = $value;
		}
	}
	return $hasChildren ? $out : $el->textContent;
}

/*
 * Interfaces the restored configuration assigns must exist, or its first boot stops at the console's interface
 * mismatch prompt. Package interfaces (NetBird's wt0, ...) that do not exist now are left unassigned and assigned
 * again once they exist (as after an upgrade); a missing physical port refuses the restore. Interfaces pfSense
 * creates from the configuration at boot (VLANs, LAGG, bridges, tunnels, PPP, ...) are not checked.
 * Returns [xml, "DESCR (if)" unassigned].
 */
function csfm_restore_check_interfaces($xml) {
	if (!class_exists('DOMDocument')) {
		return array($xml, array());
	}
	$doc = new DOMDocument();
	if (!@$doc->loadXML($xml, LIBXML_NONET)) {
		return array($xml, array());
	}
	$ifaces = (new DOMXPath($doc))->query('/pfsense/interfaces')->item(0);
	if ($ifaces === null) {
		return array($xml, array());
	}
	$virtual = '/(\.|^(vlan|lagg|bridge|gif|gre|ovpn|ppp|pppoe|pptp|l2tp|tun|tap|ipsec|enc|lo|qinq|_vip|_lloop|wg|tun_wg)|_wlan|_stf$)/';
	$detached = array();
	$names = array();
	$missing = array();
	foreach (iterator_to_array($ifaces->childNodes) as $node) {
		if ($node->nodeType !== XML_ELEMENT_NODE) {
			continue;
		}
		$if = '';
		foreach ($node->childNodes as $c) {
			if ($c->nodeType === XML_ELEMENT_NODE && $c->nodeName === 'if') {
				$if = trim($c->textContent);
			}
		}
		if ($if === '' || csfm_interface_exists($if)) {
			continue;
		}
		$key = $node->nodeName;
		$entry = csfm_dom_to_array($node);
		$descr = is_array($entry) && !empty($entry['descr']) ? $entry['descr'] : strtoupper($key);
		if ($key !== 'wan' && $key !== 'lan' && preg_match(CSFM_PACKAGE_IF_RE, $if)) {
			$detached[$key] = is_array($entry) ? $entry : array('if' => $if);
			$names[] = "{$descr} ({$if})";
			$ifaces->removeChild($node);
		} elseif (!preg_match($virtual, $if)) {
			$missing[] = "{$descr} ({$if})";
		}
	}
	if ($missing) {
		throw new Exception('Not restored: the backup assigns ' . implode(', ', $missing) . ', which this firewall does '
		    . "not have, so it would stop at the console's interface mismatch prompt after the reboot. Restore a backup "
		    . 'made on this hardware, or fix the assignments in the backup first.');
	}
	if ($detached) {
		$state = csfm_state();
		$state['detached_interfaces'] = array_merge($state['detached_interfaces'] ?? array(), $detached);
		csfm_save_state($state);
	}
	return array($detached ? $doc->saveXML() : $xml, $names);
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
	$xml = csfm_keep_local_settings($xml);
	list($xml, $unassigned) = csfm_restore_check_interfaces($xml);
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

	$note = $unassigned ? "\nLeft unassigned until the interface exists again (its package is not installed; "
	    . 'ComSense assigns it again, with its settings, once it does): ' . implode(', ', $unassigned) : '';
	csfm_report_result($client, $id, 'success', "Restored backup #{$backupId} ({$digest}); rebooting{$note}");
	csfm_log("Configuration restored from backup {$backupId}; rebooting", LOG_WARNING);
	mwexec_bg('/etc/rc.reboot');
	throw new CsfmTaskDeferred();
}
