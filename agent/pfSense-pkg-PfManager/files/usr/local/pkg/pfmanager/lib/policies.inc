<?php
/*
 * PfManager agent - policy enforcement.
 *
 * Each policy type is applied idempotently and records what it created in
 * /var/db/pfmanager/state.json, so a later revision or removal only touches
 * items this policy owns. Changes that could cut the firewall off from the
 * management server are verified afterwards and rolled back if the server
 * becomes unreachable.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');
require_once(__DIR__ . '/collect.inc');

define('PFM_RULE_PREFIX', '[PFM] ');
define('PFM_SNAPSHOT_FILE', PFM_DB_DIR . '/pre-policy-config.xml');

/* Paths a config_set policy may never modify (mirrors the server's deny list). */
$pfm_protected_paths = array(
	'system/user', 'system/group', 'system/authserver', 'cert', 'ca', 'installedpackages/pfmanager',
);

class PfmPolicyError extends Exception {
}

/* ------------------------------------------------------------------ dispatch */

function pfm_apply_policy($policy) {
	$pid = (string)$policy['id'];
	$type = $policy['type'];
	$content = $policy['content'];
	$state = pfm_state();
	$prev = $state['policies'][$pid] ?? array('type' => $type, 'items' => array(), 'saved' => array());

	$needs_verify = in_array($type, array('firewall_rules', 'system', 'config_set'), true);
	if ($needs_verify) {
		pfm_snapshot_config();
	}

	switch ($type) {
		case 'aliases':
			$record = pfm_apply_aliases($pid, $content, $prev, $state);
			break;
		case 'firewall_rules':
			$record = pfm_apply_rules($pid, $content, $prev);
			break;
		case 'system':
			$record = pfm_apply_system($pid, $content, $prev);
			break;
		case 'packages':
			$record = pfm_apply_packages($pid, $content, $prev);
			break;
		case 'config_set':
			$record = pfm_apply_config_set($pid, $content, $prev);
			break;
		default:
			throw new PfmPolicyError("Unsupported policy type '{$type}'");
	}

	if ($needs_verify && !pfm_verify_connectivity()) {
		pfm_rollback_config();
		throw new PfmPolicyError('The management server was unreachable after applying the policy; '
		    . 'the previous configuration was restored.');
	}

	$record['type'] = $type;
	$record['hash'] = $policy['hash'];
	$record['revision'] = $policy['revision'] ?? null;
	$record['name'] = $policy['name'] ?? '';
	$state = pfm_state();
	$state['policies'][$pid] = $record;
	pfm_save_state($state);
	return $record['summary'] ?? 'Applied';
}

function pfm_remove_policy($pid) {
	$pid = (string)$pid;
	$state = pfm_state();
	if (!isset($state['policies'][$pid])) {
		return 'Nothing to remove';
	}
	$prev = $state['policies'][$pid];
	switch ($prev['type']) {
		case 'aliases':
			$summary = pfm_remove_aliases($pid, $prev, $state);
			break;
		case 'firewall_rules':
			$summary = pfm_remove_rules($pid);
			break;
		case 'system':
		case 'config_set':
			$summary = pfm_restore_saved_values($prev, "PfManager: removed policy {$pid}");
			break;
		default:
			/* Packages stay installed; removing the policy only stops enforcing it. */
			$summary = 'Policy no longer enforced';
	}
	$state = pfm_state();
	unset($state['policies'][$pid]);
	pfm_save_state($state);
	return $summary;
}

/* ---------------------------------------------------------- safety net */

function pfm_snapshot_config() {
	pfm_ensure_db_dir();
	copy(pfm_config_file(), PFM_SNAPSHOT_FILE);
	chmod(PFM_SNAPSHOT_FILE, 0600);
}

function pfm_verify_connectivity() {
	$client = pfm_client();
	for ($i = 0; $i < 4; $i++) {
		sleep($i === 0 ? 3 : 5);
		try {
			$client->getJson('/ping', 10);
			return true;
		} catch (Exception $e) {
			pfm_log('Connectivity check failed: ' . $e->getMessage(), LOG_WARNING);
		}
	}
	return false;
}

function pfm_rollback_config() {
	if (!is_readable(PFM_SNAPSHOT_FILE)) {
		return;
	}
	pfm_log('Rolling back configuration after failed connectivity check', LOG_ERR);
	copy(PFM_SNAPSHOT_FILE, pfm_config_file());
	@unlink('/tmp/config.cache');
	if (function_exists('parse_config')) {
		$GLOBALS['config'] = parse_config(true);
	}
	write_config('PfManager: rolled back policy after losing contact with the server');
	pfm_reload(array('filter', 'dns', 'ntp', 'hostname'));
}

function pfm_reload($what) {
	$what = array_unique($what);
	if (in_array('hostname', $what, true)) {
		function_exists('system_hostname_configure') && system_hostname_configure();
		function_exists('system_hosts_generate') && system_hosts_generate();
	}
	if (in_array('dns', $what, true) || in_array('unbound', $what, true) || in_array('dnsmasq', $what, true)) {
		function_exists('system_resolvconf_generate') && system_resolvconf_generate();
		if (pfm_cfg_get('unbound/enable') !== null && function_exists('services_unbound_configure')) {
			services_unbound_configure();
		}
		if (pfm_cfg_get('dnsmasq/enable') !== null && function_exists('services_dnsmasq_configure')) {
			services_dnsmasq_configure();
		}
	}
	if (in_array('ntp', $what, true)) {
		function_exists('system_timezone_configure') && system_timezone_configure();
		function_exists('system_ntp_configure') && system_ntp_configure();
	}
	if (in_array('routing', $what, true)) {
		function_exists('system_routing_configure') && system_routing_configure();
	}
	if (in_array('webgui', $what, true)) {
		/* Restart the GUI in the background so this request is not cut off. */
		function_exists('mwexec_bg') && mwexec_bg('/etc/rc.restart_webgui');
	}
	if (in_array('filter', $what, true) && function_exists('filter_configure')) {
		filter_configure();
	}
}

/* ---------------------------------------------------------------- aliases */

function pfm_alias_owner($name, $state, $exceptPid) {
	foreach ($state['policies'] as $pid => $p) {
		if ((string)$pid !== (string)$exceptPid && ($p['type'] ?? '') === 'aliases'
		    && in_array($name, $p['items'] ?? array(), true)) {
			return $pid;
		}
	}
	return null;
}

function pfm_alias_in_use($name) {
	$needle = '/(^|[\s,"])' . preg_quote($name, '/') . '($|[\s,"])/';
	foreach (array('filter/rule', 'nat/rule', 'nat/outbound/rule', 'aliases/alias') as $path) {
		foreach ((array)pfm_cfg_get($path, array()) as $item) {
			if (($item['name'] ?? '') === $name) {
				continue;
			}
			foreach (array('source', 'destination') as $side) {
				foreach (array('address', 'port') as $k) {
					if (isset($item[$side][$k]) && preg_match($needle, (string)$item[$side][$k])) {
						return true;
					}
				}
			}
			foreach (array('target', 'local-port', 'address', 'sourceport', 'dstport') as $k) {
				if (isset($item[$k]) && is_string($item[$k]) && preg_match($needle, $item[$k])) {
					return true;
				}
			}
		}
	}
	return false;
}

function pfm_apply_aliases($pid, $content, $prev, $state) {
	$aliases = array_values((array)pfm_cfg_get('aliases/alias', array()));
	$index = array();
	foreach ($aliases as $i => $a) {
		$index[$a['name']] = $i;
	}
	$adopt = !empty($content['adopt_existing']);
	$names = array();
	foreach ($content['aliases'] as $a) {
		$name = $a['name'];
		if (!preg_match('/^[A-Za-z0-9_]{1,31}$/', $name)) {
			throw new PfmPolicyError("Invalid alias name '{$name}'");
		}
		$owner = pfm_alias_owner($name, $state, $pid);
		if ($owner !== null) {
			throw new PfmPolicyError("Alias {$name} is already managed by policy {$owner}");
		}
		if (isset($index[$name]) && !$adopt && !in_array($name, $prev['items'] ?? array(), true)) {
			throw new PfmPolicyError("Alias {$name} already exists on this firewall. Rename it or set adopt_existing.");
		}
		$entry = array(
			'name' => $name,
			'type' => $a['type'],
			'address' => implode(' ', $a['address'] ?? array()),
			'descr' => $a['descr'] ?? 'Managed by PfManager',
			'detail' => implode('||', $a['detail'] ?? array()),
		);
		if (in_array($a['type'], array('url', 'urltable', 'url_ports', 'urltable_ports'), true)) {
			$entry['url'] = $a['address'][0] ?? '';
			$entry['updatefreq'] = (string)($a['updatefreq'] ?? '1');
		}
		if (isset($index[$name])) {
			$aliases[$index[$name]] = $entry;
		} else {
			$aliases[] = $entry;
			$index[$name] = count($aliases) - 1;
		}
		$names[] = $name;
	}
	$removed = array();
	if ($content['remove_unlisted'] ?? true) {
		foreach (array_diff($prev['items'] ?? array(), $names) as $old) {
			if (pfm_alias_in_use($old)) {
				pfm_log("Keeping alias {$old}: still referenced by rules", LOG_WARNING);
				continue;
			}
			$aliases = array_values(array_filter($aliases, function ($a) use ($old) {
				return $a['name'] !== $old;
			}));
			$removed[] = $old;
		}
	}
	usort($aliases, function ($a, $b) { return strnatcasecmp($a['name'], $b['name']); });
	pfm_cfg_set('aliases/alias', $aliases);
	write_config("PfManager: applied alias policy {$pid}");
	pfm_reload(array('filter'));
	return array(
		'items' => $names,
		'summary' => sprintf('Set %d alias(es); removed %d', count($names), count($removed)),
	);
}

function pfm_remove_aliases($pid, $prev, $state) {
	$aliases = (array)pfm_cfg_get('aliases/alias', array());
	$removed = 0;
	$kept = array();
	foreach ($prev['items'] ?? array() as $name) {
		if (pfm_alias_in_use($name)) {
			$kept[] = $name;
			continue;
		}
		$aliases = array_filter($aliases, function ($a) use ($name) { return $a['name'] !== $name; });
		$removed++;
	}
	pfm_cfg_set('aliases/alias', array_values($aliases));
	write_config("PfManager: removed alias policy {$pid}");
	pfm_reload(array('filter'));
	$msg = "Removed {$removed} alias(es)";
	if ($kept) {
		$msg .= '; kept ' . implode(', ', $kept) . ' because rules still reference them';
	}
	return $msg;
}

/* ---------------------------------------------------------------- firewall rules */

function pfm_rule_endpoint($ep) {
	$out = array();
	if (!empty($ep['address'])) {
		$out['address'] = $ep['address'];
	} elseif (!empty($ep['network'])) {
		$out['network'] = $ep['network'];
	} else {
		$out['any'] = '';
	}
	if (!empty($ep['port'])) {
		$out['port'] = $ep['port'];
	}
	if (!empty($ep['not'])) {
		$out['not'] = '';
	}
	return $out;
}

function pfm_build_rule($pid, $r, $tracker) {
	$iface = $r['interface'];
	$rule = array(
		'id' => '',
		'tracker' => (string)$tracker,
		'type' => $r['type'] ?? 'pass',
		'interface' => $iface,
		'ipprotocol' => $r['ipprotocol'] ?? 'inet',
		'tag' => '',
		'tagged' => '',
		'max' => '',
		'max-src-nodes' => '',
		'max-src-conn' => '',
		'max-src-states' => '',
		'statetimeout' => '',
		'statetype' => 'keep state',
		'os' => '',
		'source' => pfm_rule_endpoint($r['source'] ?? array('any' => true)),
		'destination' => pfm_rule_endpoint($r['destination'] ?? array('any' => true)),
		'descr' => PFM_RULE_PREFIX . ($r['descr'] ?? ''),
		'pfmanager_policy' => $pid,
		'created' => array('time' => (string)time(), 'username' => 'PfManager'),
		'updated' => array('time' => (string)time(), 'username' => 'PfManager'),
	);
	$proto = $r['protocol'] ?? 'any';
	if ($proto !== 'any') {
		$rule['protocol'] = $proto;
	}
	if (!empty($r['log'])) {
		$rule['log'] = '';
	}
	if (!empty($r['disabled'])) {
		$rule['disabled'] = '';
	}
	if ($iface === 'floating') {
		$rule['floating'] = 'yes';
		$rule['interface'] = implode(',', $r['floating_interfaces'] ?? array('wan'));
		$rule['direction'] = $r['direction'] ?? 'any';
		$rule['quick'] = 'yes';
	}
	return $rule;
}

function pfm_is_policy_rule($rule, $pid) {
	return (string)($rule['pfmanager_policy'] ?? '') === (string)$pid;
}

function pfm_apply_rules($pid, $content, $prev) {
	$rules = array_values(array_filter((array)pfm_cfg_get('filter/rule', array()), function ($r) use ($pid) {
		return !pfm_is_policy_rule($r, $pid);
	}));
	$trackers = array();
	foreach ($rules as $r) {
		$trackers[(string)($r['tracker'] ?? '')] = true;
	}
	$tracker = time();
	$position = $content['position'] ?? 'top';

	/* Group new rules by their interface key so each block keeps policy order. */
	$groups = array();
	foreach ($content['rules'] as $r) {
		while (isset($trackers[(string)$tracker])) {
			$tracker++;
		}
		$trackers[(string)$tracker] = true;
		$built = pfm_build_rule($pid, $r, $tracker);
		$key = ($r['interface'] === 'floating') ? 'floating' : $r['interface'];
		$groups[$key][] = $built;
	}
	foreach ($groups as $key => $newRules) {
		$isFloating = ($key === 'floating');
		$positions = array();
		foreach ($rules as $i => $existing) {
			$existingFloating = !empty($existing['floating']);
			if ($isFloating ? $existingFloating : (!$existingFloating && ($existing['interface'] ?? '') === $key)) {
				$positions[] = $i;
			}
		}
		if (!$positions) {
			$at = count($rules);
		} elseif ($position === 'top') {
			$at = $positions[0];
		} else {
			$at = end($positions) + 1;
		}
		array_splice($rules, $at, 0, $newRules);
	}
	pfm_cfg_set('filter/rule', $rules);
	write_config("PfManager: applied firewall rule policy {$pid}");
	pfm_reload(array('filter'));
	return array('items' => array(), 'summary' => sprintf('Installed %d rule(s)', count($content['rules'])));
}

function pfm_remove_rules($pid) {
	$all = (array)pfm_cfg_get('filter/rule', array());
	$rules = array_values(array_filter($all, function ($r) use ($pid) {
		return !pfm_is_policy_rule($r, $pid);
	}));
	pfm_cfg_set('filter/rule', $rules);
	write_config("PfManager: removed firewall rule policy {$pid}");
	pfm_reload(array('filter'));
	return sprintf('Removed %d rule(s)', count($all) - count($rules));
}

/* ------------------------------------------------- system and config_set policies */

/* Remember the original value of a path the first time a policy changes it. */
function pfm_remember(&$saved, $path) {
	if (!array_key_exists($path, $saved)) {
		$value = pfm_cfg_get($path, null);
		$saved[$path] = array('present' => $value !== null, 'value' => $value);
	}
}

function pfm_restore_saved_values($prev, $message) {
	foreach ($prev['saved'] ?? array() as $path => $orig) {
		if (!empty($orig['present'])) {
			pfm_cfg_set($path, $orig['value']);
		} else {
			pfm_cfg_del($path);
		}
	}
	write_config($message);
	pfm_reload(array_merge(array('filter', 'dns', 'ntp', 'hostname'), $prev['reload'] ?? array()));
	return sprintf('Restored %d setting(s) to their previous values', count($prev['saved'] ?? array()));
}

function pfm_apply_system($pid, $content, $prev) {
	$saved = $prev['saved'] ?? array();
	$map = array(
		'hostname' => 'system/hostname',
		'domain' => 'system/domain',
		'timezone' => 'system/timezone',
		'timeservers' => 'system/timeservers',
		'language' => 'system/language',
	);
	$reload = array();
	foreach ($map as $key => $path) {
		if (array_key_exists($key, $content)) {
			pfm_remember($saved, $path);
			pfm_cfg_set($path, (string)$content[$key]);
		}
	}
	if (array_key_exists('hostname', $content) || array_key_exists('domain', $content)) {
		$reload[] = 'hostname';
		$reload[] = 'dns';
	}
	if (array_key_exists('timezone', $content) || array_key_exists('timeservers', $content)) {
		$reload[] = 'ntp';
	}
	if (array_key_exists('dnsservers', $content)) {
		pfm_remember($saved, 'system/dnsserver');
		foreach ($content['dnsservers'] as $ip) {
			if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
				throw new PfmPolicyError("Invalid DNS server '{$ip}'");
			}
		}
		pfm_cfg_set('system/dnsserver', array_values($content['dnsservers']));
		$reload[] = 'dns';
	}
	if (array_key_exists('dnsallowoverride', $content)) {
		pfm_remember($saved, 'system/dnsallowoverride');
		if ($content['dnsallowoverride']) {
			pfm_cfg_set('system/dnsallowoverride', '');
		} else {
			pfm_cfg_del('system/dnsallowoverride');
		}
		$reload[] = 'dns';
	}
	/* Revert keys an older revision managed but this one no longer mentions. */
	$current = array();
	foreach ($map as $key => $path) {
		if (array_key_exists($key, $content)) {
			$current[] = $path;
		}
	}
	if (array_key_exists('dnsservers', $content)) {
		$current[] = 'system/dnsserver';
	}
	if (array_key_exists('dnsallowoverride', $content)) {
		$current[] = 'system/dnsallowoverride';
	}
	foreach (array_keys($saved) as $path) {
		if (!in_array($path, $current, true)) {
			$orig = $saved[$path];
			!empty($orig['present']) ? pfm_cfg_set($path, $orig['value']) : pfm_cfg_del($path);
			unset($saved[$path]);
			$reload = array_merge($reload, array('dns', 'ntp', 'hostname'));
		}
	}
	write_config("PfManager: applied system policy {$pid}");
	pfm_reload(array_merge($reload, array('filter')));
	return array('items' => array(), 'saved' => $saved, 'summary' => 'System settings applied');
}

function pfm_path_protected($path) {
	global $pfm_protected_paths;
	foreach ($pfm_protected_paths as $p) {
		if ($path === $p || strpos($path, $p . '/') === 0) {
			return true;
		}
	}
	return false;
}

function pfm_apply_config_set($pid, $content, $prev) {
	$saved = $prev['saved'] ?? array();
	$touched = array();
	foreach ($content['items'] as $item) {
		$path = (string)$item['path'];
		if (!preg_match('#^[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-]+)*$#', $path) || pfm_path_protected($path)) {
			throw new PfmPolicyError("Path '{$path}' is not allowed");
		}
		pfm_remember($saved, $path);
		if (!empty($item['delete'])) {
			pfm_cfg_del($path);
		} else {
			pfm_cfg_set($path, $item['value']);
		}
		$touched[] = $path;
	}
	foreach (array_keys($saved) as $path) {
		if (!in_array($path, $touched, true)) {
			$orig = $saved[$path];
			!empty($orig['present']) ? pfm_cfg_set($path, $orig['value']) : pfm_cfg_del($path);
			unset($saved[$path]);
		}
	}
	$reload = array_values(array_intersect((array)($content['reload'] ?? array()),
	    array('filter', 'dns', 'ntp', 'webgui', 'hostname', 'routing', 'unbound', 'dnsmasq')));
	write_config("PfManager: applied config policy {$pid}");
	pfm_reload($reload);
	return array(
		'items' => array(),
		'saved' => $saved,
		'reload' => $reload,
		'summary' => sprintf('Set %d config value(s)', count($touched)),
	);
}

/* ---------------------------------------------------------------- packages */

function pfm_pkg_installed($name) {
	exec('/usr/sbin/pkg-static info -e ' . escapeshellarg($name), $out, $rc);
	return $rc === 0;
}

function pfm_apply_packages($pid, $content, $prev) {
	$log = array();
	foreach ((array)($content['install'] ?? array()) as $name) {
		if (!preg_match('/^pfSense-pkg-[A-Za-z0-9_.+-]{1,64}$/', $name)) {
			throw new PfmPolicyError("Invalid package name '{$name}'");
		}
		if (pfm_pkg_installed($name)) {
			continue;
		}
		list($rc, $out) = pfm_exec('/usr/local/sbin/pfSense-upgrade -y -i ' . escapeshellarg($name), 1200);
		$log[] = "install {$name}: rc={$rc}";
		if ($rc !== 0) {
			throw new PfmPolicyError("Installing {$name} failed:\n" . pfm_truncate($out, 4000));
		}
	}
	foreach ((array)($content['remove'] ?? array()) as $name) {
		if (!preg_match('/^pfSense-pkg-[A-Za-z0-9_.+-]{1,64}$/', $name) || $name === 'pfSense-pkg-PfManager') {
			throw new PfmPolicyError("Refusing to remove '{$name}'");
		}
		if (!pfm_pkg_installed($name)) {
			continue;
		}
		list($rc, $out) = pfm_exec('/usr/local/sbin/pfSense-upgrade -y -r ' . escapeshellarg($name), 1200);
		$log[] = "remove {$name}: rc={$rc}";
		if ($rc !== 0) {
			throw new PfmPolicyError("Removing {$name} failed:\n" . pfm_truncate($out, 4000));
		}
	}
	return array('items' => array(), 'summary' => $log ? implode("\n", $log) : 'All packages already in the desired state');
}
