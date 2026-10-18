<?php
/*
 * ComSense agent - inventory and health collection.
 *
 * Uses pfSense's own library functions where they exist, so the numbers match
 * what the WebGUI dashboard shows.
 */

require_once(__DIR__ . '/common.inc');

define('CSFM_UPDATE_CHECK_INTERVAL', 6 * 3600);

function csfm_sysctl($name) {
	$out = array();
	exec('/sbin/sysctl -n ' . escapeshellarg($name) . ' 2>/dev/null', $out);
	return trim(implode("\n", $out));
}

/*
 * A counter as a number. On 32-bit ARM (e.g. SG-3100) PHP integers stop at
 * 2^31-1, which byte and tick counters pass quickly, and (int) would pin them
 * there. Numeric strings + 0 give an int when it fits and a float otherwise,
 * which stays exact up to 2^53.
 */
function csfm_num($value) {
	return is_numeric($value) ? $value + 0 : 0;
}

function csfm_product_version() {
	$v = @file_get_contents('/etc/version');
	return $v === false ? '' : trim($v);
}

function csfm_edition() {
	$label = function_exists('g_get') ? (string)g_get('product_label') : '';
	if ($label === '' && isset($GLOBALS['g']['product_label'])) {
		$label = (string)$GLOBALS['g']['product_label'];
	}
	if (stripos($label, 'plus') !== false) {
		return 'plus';
	}
	/* pfSense Plus uses YY.MM versions (21.02 onward); CE stays on 2.x. */
	$major = (int)csfm_product_version();
	return $major >= 21 ? 'plus' : 'ce';
}

function csfm_collect_system() {
	$platform = '';
	if (function_exists('system_identify_specific_platform')) {
		$p = system_identify_specific_platform();
		$platform = is_array($p) ? ($p['descr'] ?? '') : '';
	}
	$hostname = csfm_cfg_get('system/hostname', '') . '.' . csfm_cfg_get('system/domain', '');
	return array(
		'hostname' => trim($hostname, '.'),
		'edition' => csfm_edition(),
		'version' => csfm_product_version(),
		'platform' => $platform,
		'serial' => function_exists('system_get_serial') ? (string)system_get_serial() : '',
		'unique_id' => function_exists('system_get_uniqueid') ? (string)system_get_uniqueid() : '',
		'kernel' => php_uname('r'),
		'arch' => php_uname('m'),
	);
}

function csfm_cpu_usage() {
	$a = preg_split('/\s+/', csfm_sysctl('kern.cp_time'));
	sleep(1);
	$b = preg_split('/\s+/', csfm_sysctl('kern.cp_time'));
	if (count($a) < 5 || count($b) < 5) {
		return null;
	}
	$total = 0;
	for ($i = 0; $i < 5; $i++) {
		$total += csfm_num($b[$i]) - csfm_num($a[$i]);
	}
	$idle = csfm_num($b[4]) - csfm_num($a[4]);
	return $total > 0 ? round(100 * ($total - $idle) / $total, 1) : null;
}

function csfm_memory_usage() {
	$total = (int)csfm_sysctl('vm.stats.vm.v_page_count');
	if ($total <= 0) {
		return null;
	}
	$free = (int)csfm_sysctl('vm.stats.vm.v_inactive_count')
	    + (int)csfm_sysctl('vm.stats.vm.v_cache_count')
	    + (int)csfm_sysctl('vm.stats.vm.v_free_count');
	return round(100 * ($total - $free) / $total, 1);
}

function csfm_states() {
	$current = null;
	$max = null;
	exec('/sbin/pfctl -si 2>/dev/null', $out);
	foreach ($out as $line) {
		if (preg_match('/current entries\s+(\d+)/', $line, $m)) {
			$current = (int)$m[1];
		}
	}
	$out = array();
	exec('/sbin/pfctl -sm 2>/dev/null', $out);
	foreach ($out as $line) {
		if (preg_match('/^states\s+hard limit\s+(\d+)/', $line, $m)) {
			$max = (int)$m[1];
		}
	}
	return array($current, $max);
}

function csfm_collect_metrics() {
	$boottime = csfm_sysctl('kern.boottime');
	$uptime = preg_match('/sec = (\d+)/', $boottime, $m) ? time() - (int)$m[1] : null;
	$total = @disk_total_space('/');
	$free = @disk_free_space('/');
	list($states, $states_max) = csfm_states();
	$load = sys_getloadavg();
	return array(
		'cpu_pct' => csfm_cpu_usage(),
		'mem_pct' => csfm_memory_usage(),
		'disk_pct' => ($total > 0) ? round(100 * ($total - $free) / $total, 1) : null,
		'load' => is_array($load) ? array_map(function ($v) { return round($v, 2); }, $load) : array(),
		'states' => $states,
		'states_max' => $states_max,
		'uptime' => $uptime,
		'mbuf' => csfm_sysctl('kern.ipc.nmbclusters'),
	);
}

function csfm_collect_interfaces() {
	$out = array();
	if (!function_exists('get_configured_interface_with_descr') || !function_exists('get_interface_info')) {
		return $out;
	}
	foreach (get_configured_interface_with_descr(true) as $name => $descr) {
		$info = get_interface_info($name);
		if (!is_array($info)) {
			continue;
		}
		$out[] = array(
			'name' => $name,
			'descr' => $descr,
			'if' => $info['if'] ?? ($info['hwif'] ?? ''),
			'status' => $info['status'] ?? '',
			'enabled' => isset($info['enable']) ? (bool)$info['enable'] : true,
			'ipaddr' => $info['ipaddr'] ?? '',
			'subnet' => $info['subnet'] ?? '',
			'ipaddrv6' => $info['ipaddrv6'] ?? '',
			'gateway' => $info['gateway'] ?? '',
			'media' => $info['media'] ?? '',
			'macaddr' => $info['macaddr'] ?? '',
			'inbytes' => csfm_num($info['inbytes'] ?? 0),
			'outbytes' => csfm_num($info['outbytes'] ?? 0),
			'inerrs' => csfm_num($info['inerrs'] ?? 0),
			'outerrs' => csfm_num($info['outerrs'] ?? 0),
			'collisions' => csfm_num($info['collisions'] ?? 0),
		);
	}
	return $out;
}

function csfm_collect_gateways() {
	$out = array();
	if (!function_exists('return_gateways_status')) {
		return $out;
	}
	$addresses = function_exists('return_gateways_array') ? return_gateways_array() : array();
	foreach ((array)return_gateways_status(true) as $name => $gw) {
		$out[] = array(
			'name' => $name,
			'gateway' => $addresses[$name]['gateway'] ?? '',
			'interface' => $addresses[$name]['friendlyiface'] ?? '',
			'monitor' => $gw['monitorip'] ?? '',
			'status' => $gw['status'] ?? '',
			'substatus' => $gw['substatus'] ?? '',
			'delay' => $gw['delay'] ?? '',
			'stddev' => $gw['stddev'] ?? '',
			'loss' => $gw['loss'] ?? '',
		);
	}
	return $out;
}

function csfm_collect_services() {
	$out = array();
	if (!function_exists('get_services') || !function_exists('get_service_status')) {
		return $out;
	}
	foreach (get_services() as $svc) {
		if (empty($svc['name'])) {
			continue;
		}
		$out[] = array(
			'name' => $svc['name'],
			'description' => $svc['description'] ?? '',
			'running' => (bool)get_service_status($svc),
			'enabled' => true,
		);
	}
	return $out;
}

function csfm_collect_carp() {
	$out = array();
	foreach ((array)csfm_cfg_get('virtualip/vip', array()) as $vip) {
		if (($vip['mode'] ?? '') !== 'carp') {
			continue;
		}
		$status = function_exists('get_carp_interface_status')
		    ? get_carp_interface_status("_vip{$vip['uniqid']}") : '';
		$out[] = array(
			'interface' => $vip['interface'] ?? '',
			'vhid' => $vip['vhid'] ?? '',
			'address' => $vip['subnet'] ?? '',
			'status' => $status,
		);
	}
	return $out;
}

function csfm_collect_packages() {
	$out = array();
	exec("/usr/sbin/pkg-static query -x '%n\t%v' '^pfSense-pkg-' 2>/dev/null", $lines);
	foreach ($lines as $line) {
		$parts = explode("\t", $line);
		if (count($parts) === 2) {
			$out[] = array('name' => $parts[0], 'version' => $parts[1]);
		}
	}
	return $out;
}

/* Package upgrades available from the configured repository. */
function csfm_outdated_packages() {
	$out = array();
	exec("/usr/sbin/pkg-static version -vRl '<' 2>/dev/null", $lines);
	foreach ($lines as $line) {
		if (preg_match('/^(\S+)-([^-\s]+)\s+<\s+needs updating \(remote has ([^)]+)\)/', $line, $m)) {
			if (strpos($m[1], 'pfSense-pkg-') === 0) {
				$out[] = array('name' => $m[1], 'installed' => $m[2], 'available' => $m[3]);
			}
		}
	}
	return $out;
}

function csfm_check_updates($force = false) {
	$state = csfm_state();
	$cached = $state['updates'] ?? null;
	if (!$force && is_array($cached) && (time() - (int)($cached['checked_ts'] ?? 0)) < CSFM_UPDATE_CHECK_INTERVAL) {
		return $cached;
	}
	$info = array(
		'installed_version' => csfm_product_version(),
		'version' => '',
		'update_available' => false,
		'packages' => array(),
		'checked_at' => gmdate('c'),
		'checked_ts' => time(),
	);
	if (function_exists('get_system_pkg_version')) {
		$sys = get_system_pkg_version(false, false);
		if (is_array($sys)) {
			$info['installed_version'] = $sys['installed_version'] ?? $info['installed_version'];
			$info['version'] = $sys['version'] ?? '';
			$info['update_available'] = (($sys['pkg_version_compare'] ?? '') === '<');
		} else {
			$info['error'] = 'Unable to query the update repository';
		}
	}
	$info['packages'] = csfm_outdated_packages();
	$state['updates'] = $info;
	csfm_save_state($state);
	return $info;
}

function csfm_config_file() {
	$dir = function_exists('g_get') ? g_get('conf_path') : ($GLOBALS['g']['conf_path'] ?? '/cf/conf');
	return ($dir ?: '/cf/conf') . '/config.xml';
}

function csfm_collect_report() {
	$state = csfm_state();
	$applied = array();
	foreach ($state['policies'] as $pid => $p) {
		$applied[(string)$pid] = $p['hash'] ?? '';
	}
	$report = array(
		'agent_version' => CSFM_AGENT_VERSION,
		'capabilities' => csfm_capabilities(),
		'system' => csfm_collect_system(),
		'metrics' => csfm_collect_metrics(),
		'interfaces' => csfm_collect_interfaces(),
		'gateways' => csfm_collect_gateways(),
		'services' => csfm_collect_services(),
		'carp' => csfm_collect_carp(),
		'packages' => csfm_collect_packages(),
		'config' => array(
			'sha256' => (string)@hash_file('sha256', csfm_config_file()),
			'revision' => (string)csfm_cfg_get('revision/description', ''),
			'time' => (int)csfm_cfg_get('revision/time', 0),
		),
		'applied_policies' => (object)$applied,
	);
	$updates = csfm_check_updates(false);
	if (is_array($updates)) {
		$report['updates'] = $updates;
	}
	return $report;
}
