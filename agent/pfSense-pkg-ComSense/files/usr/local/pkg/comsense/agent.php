<?php
/*
 * ComSense agent command line entry point.
 *
 *   php /usr/local/pkg/comsense/agent.php run      one check-in cycle (used by the daemon)
 *   php /usr/local/pkg/comsense/agent.php status   print enrollment and last check-in
 *   php /usr/local/pkg/comsense/agent.php backup   upload config.xml now
 *   php /usr/local/pkg/comsense/agent.php unenroll forget this firewall's device token
 *   php /usr/local/pkg/comsense/agent.php check-updates  query the update repository (run in the background)
 *   php /usr/local/pkg/comsense/agent.php watchdog roll back an unconfirmed change whose time is up
 *   php /usr/local/pkg/comsense/agent.php confirm  keep the change on probation (no rollback)
 *   php /usr/local/pkg/comsense/agent.php rollback undo the change on probation now
 */

if (php_sapi_name() !== 'cli') {
	exit(1);
}

require_once('config.inc');
require_once('functions.inc');
require_once('util.inc');
require_once('filter.inc');
require_once('interfaces.inc');
require_once('gwlb.inc');
require_once('system.inc');
require_once('services.inc');
require_once('service-utils.inc');
require_once('pkg-utils.inc');
require_once(__DIR__ . '/lib/agent.inc');
/* Package hooks, e.g. comsense_running() used by the service status check. */
require_once('/usr/local/pkg/comsense.inc');

define('CSFM_VERBOSE', in_array('-v', $argv, true));

$cmd = $argv[1] ?? 'run';
switch ($cmd) {
	case 'run':
		try {
			echo csfm_cycle() . "\n";
		} catch (Throwable $e) {
			/* Shown on the Status page and by "status", instead of failing silently every cycle. */
			csfm_record_error('Agent cycle failed: ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')');
			fwrite(STDERR, (string)$e . "\n");
			exit(1);
		}
		break;
	case 'status':
		$creds = csfm_credentials();
		$state = csfm_state();
		echo json_encode(array(
			'enrolled' => csfm_is_enrolled(),
			'device_id' => $creds['device_id'] ?? null,
			'server_url' => csfm_settings()['server_url'] ?? null,
			'device_status' => $state['device_status'] ?? null,
			'last_checkin' => $state['last_checkin'] ?? null,
			'last_error' => $state['last_error'] ?? null,
			'capabilities' => csfm_capabilities(),
			'managed_policies' => array_keys($state['policies']),
			'change_on_probation' => csfm_guard(),
			'last_rollback' => $state['last_rollback'] ?? null,
		), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
		break;
	case 'check-updates':
		echo json_encode(csfm_check_updates(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
		break;
	case 'watchdog':
		echo csfm_guard_watchdog() . "\n";
		break;
	case 'confirm':
		csfm_guard_confirm('confirmed by hand on the firewall');
		echo "Change confirmed; it will not be rolled back.\n";
		break;
	case 'rollback':
		$rec = csfm_guard_rollback('rolled back by hand on the firewall');
		echo $rec ? "Rolled back: {$rec['changes']}\n" : "No change on probation.\n";
		break;
	case 'backup':
		if (!csfm_is_enrolled()) {
			fwrite(STDERR, "Not enrolled\n");
			exit(1);
		}
		$resp = csfm_upload_backup(csfm_client(), 'manual');
		echo json_encode($resp) . "\n";
		break;
	case 'unenroll':
		csfm_forget_credentials();
		echo "Credentials removed. Enter a new enrollment key to reconnect.\n";
		break;
	default:
		fwrite(STDERR, "Usage: agent.php run|status|backup|unenroll|check-updates|watchdog|confirm|rollback [-v]\n");
		exit(2);
}
