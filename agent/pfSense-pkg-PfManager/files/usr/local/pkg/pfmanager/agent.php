<?php
/*
 * PfManager agent command line entry point.
 *
 *   php /usr/local/pkg/pfmanager/agent.php run      one check-in cycle (used by the daemon)
 *   php /usr/local/pkg/pfmanager/agent.php status   print enrollment and last check-in
 *   php /usr/local/pkg/pfmanager/agent.php backup   upload config.xml now
 *   php /usr/local/pkg/pfmanager/agent.php unenroll forget this firewall's device token
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

define('PFM_VERBOSE', in_array('-v', $argv, true));

$cmd = $argv[1] ?? 'run';
switch ($cmd) {
	case 'run':
		echo pfm_cycle() . "\n";
		break;
	case 'status':
		$creds = pfm_credentials();
		$state = pfm_state();
		echo json_encode(array(
			'enrolled' => pfm_is_enrolled(),
			'device_id' => $creds['device_id'] ?? null,
			'server_url' => pfm_settings()['server_url'] ?? null,
			'device_status' => $state['device_status'] ?? null,
			'last_checkin' => $state['last_checkin'] ?? null,
			'last_error' => $state['last_error'] ?? null,
			'capabilities' => pfm_capabilities(),
			'managed_policies' => array_keys($state['policies']),
		), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
		break;
	case 'backup':
		if (!pfm_is_enrolled()) {
			fwrite(STDERR, "Not enrolled\n");
			exit(1);
		}
		$resp = pfm_upload_backup(pfm_client(), 'manual');
		echo json_encode($resp) . "\n";
		break;
	case 'unenroll':
		pfm_forget_credentials();
		echo "Credentials removed. Enter a new enrollment key to reconnect.\n";
		break;
	default:
		fwrite(STDERR, "Usage: agent.php run|status|backup|unenroll [-v]\n");
		exit(2);
}
