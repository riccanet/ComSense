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
/* Pretend to be another agent version (self-update tests). */
if (getenv('CSFM_TEST_AGENT_VERSION')) {
	define('CSFM_AGENT_VERSION', getenv('CSFM_TEST_AGENT_VERSION'));
}
define('CSFM_CFG_JSON', $dir . '/config.json');
define('CSFM_ACTIONS_LOG', $dir . '/actions.log');
define('CSFM_GUARD_DIR', $dir . '/guard');
define('CSFM_LOG_DIR', $dir . '/logs');
/* bectl: lists the lines of $dir/bes.txt (name, flags, mountpoint, space, created; tab-separated); destroy
   removes one and logs it. */
define('CSFM_BECTL', $dir . '/bectl');
if (!file_exists(CSFM_BECTL)) {
	$bes = escapeshellarg($dir . '/bes.txt');
	$log = escapeshellarg($dir . '/actions.log');
	file_put_contents(CSFM_BECTL, "#!/bin/sh\n"
	    . "if [ \"\$1\" = list ]; then [ -f {$bes} ] && cat {$bes}; exit 0; fi\n"
	    . "if [ \"\$1\" = destroy ]; then echo \"bectl destroy \$2 \$3\" >> {$log}; "
	    . "grep -v \"^\$3\t\" {$bes} > {$bes}.new; mv {$bes}.new {$bes}; exit 0; fi\nexit 1\n");
	chmod(CSFM_BECTL, 0755);
}
/* A firewall short of space for an upgrade (bytes). */
if (getenv('CSFM_TEST_UPGRADE_MIN_FREE')) {
	define('CSFM_UPGRADE_MIN_FREE', (int)getenv('CSFM_TEST_UPGRADE_MIN_FREE'));
}
/* pfSense-upgrade -c: records the PATH it was run with and reports a new version (exit 2). */
define('CSFM_UPGRADE_BIN', $dir . '/pfSense-upgrade');
if (!file_exists(CSFM_UPGRADE_BIN)) {
	file_put_contents(CSFM_UPGRADE_BIN, "#!/bin/sh\necho \"\$PATH\" > " . escapeshellarg($dir . '/upgrade-path') . "\n"
	    . "echo \"\$SSL_CERT_DIR\" > " . escapeshellarg($dir . '/upgrade-certdir') . "\n"
	    . "echo 'Messages:'\necho '>>> Updating repositories metadata...'\necho '2.7.2 version of pfSense is available'\nexit 2\n");
	chmod(CSFM_UPGRADE_BIN, 0755);
}
/* pkg-static: "config abi" prints $dir/pkg-abi (e.g. FreeBSD:16:aarch64, a newer branch's repository); the rest
   is logged and fails. */
define('CSFM_PKG', $dir . '/pkg-static');
if (!file_exists(CSFM_PKG)) {
	$abi = escapeshellarg($dir . '/pkg-abi');
	$log = escapeshellarg($dir . '/actions.log');
	$installed = escapeshellarg($dir . '/installed-');
	file_put_contents(CSFM_PKG, "#!/bin/sh\nif [ \"\$1 \$2\" = \"config abi\" ] && [ -f {$abi} ]; then cat {$abi}; exit 0; fi\n"
	    . "if [ \"\$1 \$2\" = \"info -e\" ] && [ -f {$installed}\"\$3\" ]; then exit 0; fi\n"
	    . "echo \"pkg-static \$*\" >> {$log}\nexit 1\n");
	chmod(CSFM_PKG, 0755);
}
/* ARP table and DHCP leases: arp prints $dir/arp.txt; lease files live in $dir. Sent with every check-in. */
define('CSFM_ARP_BIN', $dir . '/arp');
if (!file_exists(CSFM_ARP_BIN)) {
	file_put_contents(CSFM_ARP_BIN, "#!/bin/sh\n[ \"\$1\" = -an ] && cat " . escapeshellarg($dir . '/arp.txt') . " 2>/dev/null\nexit 0\n");
	chmod(CSFM_ARP_BIN, 0755);
}
/* pfctl: -si reports $dir/states.txt as the current state count; -nf fails on a ruleset naming BADTABLE. */
define('CSFM_RULES_DEBUG', $dir . '/rules.debug');
/* /etc/rc.filter_configure_sync: "generates" the ruleset from the saved configuration (its aliases), so pfctl
   below rejects it while any alias is named BADTABLE. */
define('CSFM_FILTER_SYNC_BIN', $dir . '/rc.filter_configure_sync');
if (!file_exists(CSFM_FILTER_SYNC_BIN)) {
	file_put_contents(CSFM_FILTER_SYNC_BIN, "#!/bin/sh\nphp -r " . escapeshellarg('$c = json_decode(file_get_contents($argv[1]), true); '
	    . 'file_put_contents($argv[2], json_encode($c["aliases"] ?? array()));') . ' ' . escapeshellarg(CSFM_CFG_JSON) . ' '
	    . escapeshellarg($dir . '/rules.debug') . "\necho filter_configure_sync >> " . escapeshellarg($dir . '/actions.log') . "\n");
	chmod(CSFM_FILTER_SYNC_BIN, 0755);
}
define('CSFM_PFCTL', $dir . '/pfctl');
if (!file_exists(CSFM_PFCTL)) {
	$states = escapeshellarg($dir . '/states.txt');
	file_put_contents(CSFM_PFCTL, "#!/bin/sh\nif [ \"\$1\" = -si ]; then echo \"  current entries \$(cat {$states} 2>/dev/null || echo 5)\"; exit 0; fi\n"
	    . "if [ \"\$1\" = -nf ] && grep -q BADTABLE \"\$2\"; then echo \"\$2:107: cannot load \\\"/var/db/aliastables/BADTABLE.txt\\\": Invalid argument\"; exit 1; fi\nexit 0\n");
	chmod(CSFM_PFCTL, 0755);
}
/* pfBlockerNG's command line: logs each run; "updateip" builds pfB_<Region>_v4/_v6 for each region with
   countries selected (and drops other pfB_ aliases), saving config.xml itself as pfBlockerNG does. */
define('CSFM_PHP_BIN', PHP_BINARY);
define('CSFM_PFB_SCRIPT', $dir . '/pfblockerng.php');
define('CSFM_GEOIP_DB', $dir . '/GeoLite2-Country.mmdb');
define('CSFM_HEARTBEAT_EVERY', 1);  /* long steps report progress every second here (60 on a firewall) */  /* absent: the first GeoIP apply downloads it */
if (!file_exists(CSFM_PFB_SCRIPT)) {
	file_put_contents(CSFM_PFB_SCRIPT, <<<'PHP'
<?php
$dir = __DIR__;
file_put_contents("$dir/actions.log", "pfblockerng {$argv[1]}\n", FILE_APPEND);
if (($argv[1] ?? '') !== 'updateip') { exit(0); }
sleep(3);  /* long enough for the agent to report progress (every second in tests) */
/* Like pfBlockerNG restarting its filterlog service on the way out: something that outlives this run and keeps
   its output open. The agent must take the run as finished when this process exits. */
exec('sleep 25 1>&2 &');
$xmlf = "$dir/conf/config.xml";
$xml = file_get_contents($xmlf);
preg_match('/<!-- (\S+) -->/', $xml, $m);
$c = json_decode(base64_decode($m[1]), true);
$aliases = array_values(array_filter($c['aliases']['alias'] ?? array(), function ($a) { return strpos($a['name'] ?? '', 'pfB_') !== 0; }));
$names = array('africa' => 'Africa', 'antarctica' => 'Antarctica', 'asia' => 'Asia', 'europe' => 'Europe',
	'northamerica' => 'NAmerica', 'oceania' => 'Oceania', 'southamerica' => 'SAmerica');
foreach ($names as $s => $n) {
	/* As pfBlockerNG does: an alias for every region with countries selected, whatever its action. */
	if (($c['installedpackages']["pfblockerng{$s}"]['config'][0]['countries4'] ?? '') !== '') {
		foreach (array(4, 6) as $v) {
			$aliases[] = array('name' => "pfB_{$n}_v{$v}", 'type' => 'urltable', 'url' => "https://127.0.0.1:443/pfblockerng/pfblockerng.php?pfb=pfB_{$n}_v{$v}");
		}
	}
}
if ($aliases) { $c['aliases'] = array('alias' => $aliases); } else { unset($c['aliases']); }
file_put_contents("$dir/config.json", json_encode($c, JSON_PRETTY_PRINT));
file_put_contents($xmlf, str_replace($m[1], base64_encode(json_encode($c)), $xml));
PHP
	);
}
define('CSFM_ISC_LEASES', $dir . '/dhcpd.leases');
define('CSFM_KEA_LEASES', $dir . '/kea-dhcp4.leases');
define('CSFM_NEIGHBORS_EVERY', (int)(getenv('CSFM_TEST_NEIGHBORS_EVERY') ?: 0));
/* pfSense-upgrade's output (the test writes what an upgrade left behind). */
define('CSFM_UPGRADE_LOG', $dir . '/upgrade.log');
define('CSFM_PFSENSE_UPGRADE_LOG', $dir . '/pf-upgrade.log');
/* Network interfaces that exist on the "firewall": one per line in $dir/ifaces.txt. */
function does_interface_exist($if) {
	if (preg_match('/^vtnet\d+$/', $if)) {
		return true;  /* the test firewall's own NICs */
	}
	$list = @file(getenv('CSFM_TEST_DIR') . '/ifaces.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: array();
	return in_array($if, $list, true);
}
/* Fast timings: no settle delays, and a probation window the test can control. */
define('CSFM_VERIFY_DELAY', 0);
define('CSFM_RETRY_DELAY', 0);
define('CSFM_GUARD_WINDOW', (int)(getenv('CSFM_TEST_GUARD_WINDOW') ?: 300));
/* Test runs are seconds apart; by default the next check-in confirms the previous change. */
define('CSFM_GUARD_CONFIRM_AFTER', (int)(getenv('CSFM_TEST_CONFIRM_AFTER') ?: 0));

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
	$pkgs = '';
	if (isset($config['installedpackages']['comsense'])) {
		/* The agent's own settings as real XML (a restore keeps the live ones; tasks.inc). */
		$fields = '';
		foreach ((array)($config['installedpackages']['comsense']['config'][0] ?? array()) as $k => $v) {
			if (is_scalar($v) && preg_match('/^[a-z_]+$/', $k)) {
				$fields .= "<{$k}>" . htmlspecialchars((string)$v) . "</{$k}>";
			}
		}
		$pkgs = "\t<installedpackages><comsense><config>{$fields}</config></comsense></installedpackages>\n";
	}
	/* Interface assignments as real XML too (a restore checks them; tasks.inc). */
	$ifs = '';
	foreach ((array)($config['interfaces'] ?? array()) as $key => $iface) {
		$fields = '';
		foreach ((array)$iface as $k => $v) {
			if (is_scalar($v) && preg_match('/^[a-z_]+$/', $k)) {
				$fields .= "<{$k}>" . htmlspecialchars((string)$v) . "</{$k}>";
			}
		}
		$ifs .= "<{$key}>{$fields}</{$key}>";
	}
	$ifs = $ifs === '' ? '' : "\t<interfaces>{$ifs}</interfaces>\n";
	return "<?xml version=\"1.0\"?>\n<pfsense>\n\t<version>23.3</version>\n"
	    . "\t<revision><description>{$desc}</description></revision>\n" . $ifs . $pkgs
	    . "\t<!-- " . base64_encode(json_encode($config)) . " -->\n</pfsense>\n";
}

function write_config($desc = '') {
	global $config;
	$config['revision'] = array('description' => $desc, 'time' => time());
	file_put_contents(CSFM_CFG_JSON, json_encode($config, JSON_PRETTY_PRINT));
	file_put_contents(g_get('conf_path') . '/config.xml', csfm_test_render_xml());
	csfm_test_action("write_config: {$desc}");
}

/* Reads the config back from config.xml (where the rendered copy embeds it), like pfSense does. */
/* Not parse_config(): current pfSense (2.7 and later) no longer has it, and the agent must not depend on it. */
function csfm_test_read_config_xml() {
	$xml = (string)@file_get_contents(g_get('conf_path') . '/config.xml');
	if (preg_match('/<!-- (\S+) -->/', $xml, $m)) {
		return json_decode(base64_decode($m[1]), true) ?: array();
	}
	return array();
}

/* pfSense 2.7 and later: config.xml read again into the global configuration (what the agent must use). */
function config_read_file($parse = false, $force = false) {
	global $config;
	$config = csfm_test_read_config_xml();
	return $config;
}

function g_get($key) {
	$vals = array('conf_path' => getenv('CSFM_TEST_DIR') . '/conf', 'product_label' => 'pfSense');
	return $vals[$key] ?? null;
}

function filter_configure() { csfm_test_action('filter_configure'); }
/* Like pfSense's: needs functions (filter_generate_dummynet_rules...) the agent does not load; the agent must not call it. */
function filter_configure_sync() { throw new Error('Call to undefined function filter_generate_dummynet_rules()'); }
function services_dhcpd_configure() { csfm_test_action('services_dhcpd_configure'); }
function system_resolvconf_generate() { csfm_test_action('system_resolvconf_generate'); }
function system_timezone_configure() { csfm_test_action('system_timezone_configure'); }
function system_ntp_configure() { csfm_test_action('system_ntp_configure'); }
function mwexec_bg($cmd) { csfm_test_action("mwexec_bg: {$cmd}"); }
function send_event($cmd) { csfm_test_action("send_event: {$cmd}"); }
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
function get_services() {
	return array(array('name' => 'unbound', 'description' => 'DNS Resolver'),
	    array('name' => 'comsense', 'description' => 'ComSense agent'));
}
/* Like pfSense: a package service's status snippet calls a function from its include file. */
function get_service_status($svc) {
	if ($svc['name'] === 'comsense') {
		return comsense_status_from_include_file();
	}
	return true;
}
function service_control_restart($name, $extras) { csfm_test_action("restart {$name}"); return "{$name} has been restarted."; }
function get_system_pkg_version($baseonly = false, $use_cache = true) {
	return array('version' => '2.7.2-RELEASE', 'installed_version' => '2.7.0-RELEASE', 'pkg_version_compare' => '<');
}

define('DYNDNS_PROVIDER_VALUES', 'cloudflare cloudflare-v6 custom namecheap noip');
define('DYNDNS_PROVIDER_DESCRIPTIONS', 'Cloudflare,Cloudflare (v6),Custom,Namecheap,No-IP');

/* System > Update branches, as pkg-utils.inc lists them. */
function pkg_list_repos() {
	return array(
		array('name' => 'Stable', 'path' => '/usr/local/share/pfSense/pkg/repos/pfSense-repo.conf', 'descr' => 'Latest stable version (2.7.2)', 'default' => true),
		array('name' => 'Devel', 'path' => '/usr/local/share/pfSense/pkg/repos/pfSense-repo-devel.conf', 'descr' => 'Latest development snapshots (2.8.0)'),
	);
}
function pkg_switch_repo($path) { csfm_test_action("pkg_switch_repo {$path}"); }

require_once(getenv('CSFM_AGENT_DIR') . '/lib/agent.inc');

@mkdir(g_get('conf_path'), 0700, true);
/* config.xml always matches the config, as on a firewall (tests edit config.json directly). */
file_put_contents(g_get('conf_path') . '/config.xml', csfm_test_render_xml());

switch ($argv[1] ?? 'run') {
	case 'run':
		echo csfm_cycle() . "\n";
		break;
	case 'check-updates':
		echo json_encode(csfm_check_updates()) . "\n";
		break;
	case 'terminal':
		echo csfm_terminal_session((string)($argv[2] ?? '')) . "\n";
		break;
	case 'disable-recovery':
		csfm_disable_recovery();
		break;
	case 'wait':
		$r = csfm_wait_for_work((int)($argv[2] ?? 60));
		echo $r . "\n";
		exit($r === 'wake' ? 0 : ($r === 'idle' ? 1 : 2));
	case 'watchdog':
		echo csfm_guard_watchdog() . "\n";
		break;
	case 'state':
		echo json_encode(array('credentials' => csfm_credentials(), 'state' => csfm_state())) . "\n";
		break;
}
