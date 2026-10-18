<?php
/*
 * PfManager agent - inventory and health collection.
 *
 * Uses pfSense's own library functions where they exist, so the numbers match
 * what the WebGUI dashboard shows.
 */

require_once(__DIR__ . '/common.inc');

define('PFM_UPDATE_CHECK_INTERVAL', 6 * 3600);

function pfm_sysctl($name) {
	$out = array();
	exec('/sbin/sysctl -n ' . escapeshellarg($name) . ' 2>/dev/null', $out);
	return trim(implode("\n", $out));
}

function pfm_product_version() {
	$v = @file_get_contents('/etc/version');
	return $v === false ? '' : trim($v);
}

function pfm_edition() {
	$label = function_exists('g_get') ? (string)g_get('product_label') : '';
	if ($label === '' && isset($GLOBALS['g']['product_label'])) {
		$label = (string)$GLOBALS['g']['product_label'];
	}
	if (stripos($label, 'plus') !== false) {
		return 'plus';
	}
	/* pfSense Plus uses YY.MM versions (21.02 onward); CE stays on 2.x. */
	$major = (int)pfm_product_version();
	return $major >= 21 ? 'plus' : 'ce';
}

function pfm_collect_system() {
	$platform = '';
	if (function_exists('system_identify_specific_platform')) {
		$p = system_identify_specific_platform();
		$platform = is_array($p) ? ($p['descr'] ?? '') : '';
	}
	$hostname = pfm_cfg_get('system/hostname', '') . '.' . pfm_cfg_get('system/domain', '');
	return array(
		'hostname' => trim($hostname, '.'),
		'edition' => pfm_edition(),
		'version' => pfm_product_version(),
		'platform' => $platform,
		'serial' => function_exists('system_get_serial') ? (string)system_get_serial() : '',
		'unique_id' => function_exists('system_get_uniqueid') ? (string)system_get_uniqueid() : '',
		'kernel' => php_uname('r'),
		'arch' => php_uname('m'),
	);
}

function pfm_cpu_usage() {
	$a = preg_split('/\s+/', pfm_sysctl('kern.cp_time'));
	sleep(1);
	$b = preg_split('/\s+/', pfm_sysctl('kern.cp_time'));
	if (count($a) < 5 || count($b) < 5) {
		return null;
	}
	$total = 0;
	for ($i = 0; $i < 5; $i++) {
		$total += (int)$b[$i] - (int)$a[$i];
	}
	$idle = (int)$b[4] - (int)$a[4];
	return $total > 0 ? round(100 * ($total - $idle) / $total, 1) : null;
}

function pfm_memory_usage() {
	$total = (int)pfm_sysctl('vm.stats.vm.v_page_count');
	if ($total <= 0) {
		return null;
	}
	$free = (int)pfm_sysctl('vm.stats.vm.v_inactive_count')
	    + (int)pfm_sysctl('vm.stats.vm.v_cache_count')
	    + (int)pfm_sysctl('vm.stats.vm.v_free_count');
	return round(100 * ($total - $free) / $total, 1);
}

function pfm_states() {
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

function pfm_collect_metrics() {
	$boottime = pfm_sysctl('kern.boottime');
	$uptime = preg_match('/sec = (\d+)/', $boottime, $m) ? time() - (int)$m[1] : null;
	$total = @disk_total_space('/');
	$free = @disk_free_space('/');
	list($states, $states_max) = pfm_states();
	$load = sys_getloadavg();
	return array(
		'cpu_pct' => pfm_cpu_usage(),
		'mem_pct' => pfm_memory_usage(),
		'disk_pct' => ($total > 0) ? round(100 * ($total - $free) / $total, 1) : null,
		'load' => is_array($load) ? array_map(function ($v) { return round($v, 2); }, $load) : array(),
		'states' => $states,
		'states_max' => $states_max,
		'uptime' => $uptime,
		'mbuf' => pfm_sysctl('kern.ipc.nmbclusters'),
	);
}

function pfm_collect_interfaces() {
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
			'inbytes' => (int)($info['inbytes'] ?? 0),
			'outbytes' => (int)($info['outbytes'] ?? 0),
			'inerrs' => (int)($info['inerrs'] ?? 0),
			'outerrs' => (int)($info['outerrs'] ?? 0),
			'collisions' => (int)($info['collisions'] ?? 0),
		);
	}
	return $out;
}

function pfm_collect_gateways() {
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

function pfm_collect_services() {
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

function pfm_collect_carp() {
	$out = array();
	foreach ((array)pfm_cfg_get('virtualip/vip', array()) as $vip) {
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

function pfm_collect_packages() {
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
function pfm_outdated_packages() {
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

function pfm_check_updates($force = false) {
	$state = pfm_state();
	$cached = $state['updates'] ?? null;
	if (!$force && is_array($cached) && (time() - (int)($cached['checked_ts'] ?? 0)) < PFM_UPDATE_CHECK_INTERVAL) {
		return $cached;
	}
	$info = array(
		'installed_version' => pfm_product_version(),
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
	$info['packages'] = pfm_outdated_packages();
	$state['updates'] = $info;
	pfm_save_state($state);
	return $info;
}

function pfm_config_file() {
	$dir = function_exists('g_get') ? g_get('conf_path') : ($GLOBALS['g']['conf_path'] ?? '/cf/conf');
	return ($dir ?: '/cf/conf') . '/config.xml';
}

function pfm_collect_report() {
	$state = pfm_state();
	$applied = array();
	foreach ($state['policies'] as $pid => $p) {
		$applied[(string)$pid] = $p['hash'] ?? '';
	}
	$report = array(
		'agent_version' => PFM_AGENT_VERSION,
		'capabilities' => pfm_capabilities(),
		'system' => pfm_collect_system(),
		'metrics' => pfm_collect_metrics(),
		'interfaces' => pfm_collect_interfaces(),
		'gateways' => pfm_collect_gateways(),
		'services' => pfm_collect_services(),
		'carp' => pfm_collect_carp(),
		'packages' => pfm_collect_packages(),
		'config' => array(
			'sha256' => (string)@hash_file('sha256', pfm_config_file()),
			'revision' => (string)pfm_cfg_get('revision/description', ''),
			'time' => (int)pfm_cfg_get('revision/time', 0),
		),
		'applied_policies' => (object)$applied,
	);
	$updates = pfm_check_updates(false);
	if (is_array($updates)) {
		$report['updates'] = $updates;
	}
	return $report;
}
