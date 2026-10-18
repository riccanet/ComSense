<?php
/*
 * Runs the real agent code outside pfSense by stubbing the pfSense functions
 * it calls. The fake config.xml lives in $CSFM_TEST_DIR/config.json and is
 * written back on write_config(), so successive runs behave like a firewall.
 *
 *   CSFM_TEST_DIR=/tmp/x php harness.php run|enroll-check|config
 */

$dir = getenv('CSFM_TEST_DIR');
if (!$dir) {
	fwrite(STDERR, "CSFM_TEST_DIR is not set\n");
	exit(2);
}
define('CSFM_DB_DIR', $dir . '/db');
define('CSFM_CFG_JSON', $dir . '/config.json');
define('CSFM_ACTIONS_LOG', $dir . '/actions.log');

$config = json_decode((string)@file_get_contents(CSFM_CFG_JSON), true) ?: array();

function csfm_test_action($what) {
	file_put_contents(CSFM_ACTIONS_LOG, $what . "\n", FILE_APPEND);
}

function config_get_path($path, $default = null) {
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

function config_set_path($path, $value) {
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

function config_del_path($path) {
	global $config;
	$parts = explode('/', $path);
	$last = array_pop($parts);
	$node = &$config;
	foreach ($parts as $part) {
		if (!isset($node[$part])) {
			return;
		}
		$node = &$node[$part];
	}
	unset($node[$last]);
}

function csfm_test_render_xml() {
	global $config;
	$desc = htmlspecialchars($config['revision']['description'] ?? 'initial');
	return "<?xml version=\"1.0\"?>\n<pfsense>\n\t<version>23.3</version>\n"
	    . "\t<revision><description>{$desc}</description></revision>\n"
	    . "\t<!-- " . base64_encode(json_encode($config)) . " -->\n</pfsense>\n";
}

function write_config($desc = '') {
	global $config;
	$config['revision'] = array('description' => $desc, 'time' => time());
	file_put_contents(CSFM_CFG_JSON, json_encode($config, JSON_PRETTY_PRINT));
	file_put_contents(g_get('conf_path') . '/config.xml', csfm_test_render_xml());
	csfm_test_action("write_config: {$desc}");
}

function g_get($key) {
	$vals = array('conf_path' => getenv('CSFM_TEST_DIR') . '/conf', 'product_label' => 'pfSense');
	return $vals[$key] ?? null;
}

function filter_configure() { csfm_test_action('filter_configure'); }
function system_resolvconf_generate() { csfm_test_action('system_resolvconf_generate'); }
function system_timezone_configure() { csfm_test_action('system_timezone_configure'); }
function system_ntp_configure() { csfm_test_action('system_ntp_configure'); }
function mwexec_bg($cmd) { csfm_test_action("mwexec_bg: {$cmd}"); }
function mwexec($cmd) { csfm_test_action("mwexec: {$cmd}"); return 0; }
function system_get_uniqueid() { return 'e2e-unique-id'; }
function system_get_serial() { return 'E2E-SERIAL'; }
function system_identify_specific_platform() { return array('descr' => 'Test VM'); }
function get_configured_interface_with_descr($all = false) { return array('wan' => 'WAN', 'lan' => 'LAN'); }
function get_interface_info($if) {
	return array('if' => $if === 'wan' ? 'vtnet0' : 'vtnet1', 'status' => 'up',
	    'ipaddr' => $if === 'wan' ? '198.51.100.20' : '192.168.1.1', 'subnet' => '24',
	    'inbytes' => 1000, 'outbytes' => 2000);
}
function return_gateways_status($byname = false) {
	return array('WAN_DHCP' => array('monitorip' => '198.51.100.1', 'status' => 'online', 'delay' => '1ms', 'loss' => '0.0%'));
}
function return_gateways_array() { return array('WAN_DHCP' => array('gateway' => '198.51.100.1', 'friendlyiface' => 'wan')); }
function get_services() { return array(array('name' => 'unbound', 'description' => 'DNS Resolver')); }
function get_service_status($svc) { return true; }
function service_control_restart($name, $extras) { csfm_test_action("restart {$name}"); return "{$name} has been restarted."; }
function get_system_pkg_version($baseonly = false, $use_cache = true) {
	return array('version' => '2.7.2-RELEASE', 'installed_version' => '2.7.0-RELEASE', 'pkg_version_compare' => '<');
}

require_once(getenv('CSFM_AGENT_DIR') . '/lib/agent.inc');

@mkdir(g_get('conf_path'), 0700, true);
if (!file_exists(g_get('conf_path') . '/config.xml')) {
	file_put_contents(g_get('conf_path') . '/config.xml', csfm_test_render_xml());
}

switch ($argv[1] ?? 'run') {
	case 'run':
		echo csfm_cycle() . "\n";
		break;
	case 'state':
		echo json_encode(array('credentials' => csfm_credentials(), 'state' => csfm_state())) . "\n";
		break;
}
