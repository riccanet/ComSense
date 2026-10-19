<?php
/*
 * ComSense agent - policy enforcement.
 *
 * Each policy type is applied idempotently and records what it created in
 * /var/db/comsense/state.json, so a later revision or removal only touches
 * items this policy owns. Every apply and removal runs under the change
 * guard (guard.inc), which rolls it back if the firewall loses contact with
 * the management server.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');
require_once(__DIR__ . '/collect.inc');

define('CSFM_RULE_PREFIX', '[CSFM] ');

/* Paths a config_set policy may never modify (mirrors the server's deny list). */
$csfm_protected_paths = array(
	'system/user', 'system/group', 'system/authserver', 'cert', 'ca', 'installedpackages/comsense',
);

class CsfmPolicyError extends Exception {
}

/* ------------------------------------------------------------------ dispatch */

function csfm_apply_policy($policy) {
	$pid = (string)$policy['id'];
	$type = $policy['type'];
	$content = $policy['content'];
	$state = csfm_state();
	$prev = $state['policies'][$pid] ?? array('type' => $type, 'items' => array(), 'saved' => array());

	switch ($type) {
		case 'aliases':
			$record = csfm_apply_aliases($pid, $content, $prev, $state);
			break;
		case 'firewall_rules':
			$record = csfm_apply_rules($pid, $content, $prev);
			break;
		case 'system':
			$record = csfm_apply_system($pid, $content, $prev);
			break;
		case 'packages':
			$record = csfm_apply_packages($pid, $content, $prev);
			break;
		case 'config_set':
			$record = csfm_apply_config_set($pid, $content, $prev);
			break;
		case 'port_forward':
			$record = csfm_apply_port_forwards($pid, $content);
			break;
		case 'notifications':
			$record = csfm_apply_notifications($content, $prev);
			break;
		default:
			throw new CsfmPolicyError("Unsupported policy type '{$type}'");
	}

	$record['type'] = $type;
	$record['hash'] = $policy['hash'];
	$record['revision'] = $policy['revision'] ?? null;
	$record['name'] = $policy['name'] ?? '';
	$state = csfm_state();
	$state['policies'][$pid] = $record;
	csfm_save_state($state);
	return $record['summary'] ?? 'Applied';
}

function csfm_remove_policy($pid) {
	$pid = (string)$pid;
	$state = csfm_state();
	if (!isset($state['policies'][$pid])) {
		return 'Nothing to remove';
	}
	$prev = $state['policies'][$pid];
	switch ($prev['type']) {
		case 'aliases':
			$summary = csfm_remove_aliases($pid, $prev, $state);
			break;
		case 'firewall_rules':
			$summary = csfm_remove_rules($pid);
			break;
		case 'port_forward':
			$summary = csfm_remove_port_forwards($pid);
			break;
		case 'system':
		case 'config_set':
		case 'notifications':
			$summary = csfm_restore_saved_values($prev, "ComSense: removed policy {$pid}");
			break;
		default:
			/* Packages stay installed; removing the policy only stops enforcing it. */
			$summary = 'Policy no longer enforced';
	}
	$state = csfm_state();
	unset($state['policies'][$pid]);
	csfm_save_state($state);
	return $summary;
}

/* ------------------------------------------------------------- reloads */

function csfm_reload($what) {
	$what = array_unique($what);
	if (in_array('hostname', $what, true)) {
		function_exists('system_hostname_configure') && system_hostname_configure();
		function_exists('system_hosts_generate') && system_hosts_generate();
	}
	if (in_array('dns', $what, true) || in_array('unbound', $what, true) || in_array('dnsmasq', $what, true)) {
		function_exists('system_resolvconf_generate') && system_resolvconf_generate();
		if (csfm_cfg_get('unbound/enable') !== null && function_exists('services_unbound_configure')) {
			services_unbound_configure();
		}
		if (csfm_cfg_get('dnsmasq/enable') !== null && function_exists('services_dnsmasq_configure')) {
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

function csfm_alias_owner($name, $state, $exceptPid) {
	foreach ($state['policies'] as $pid => $p) {
		if ((string)$pid !== (string)$exceptPid && ($p['type'] ?? '') === 'aliases'
		    && in_array($name, $p['items'] ?? array(), true)) {
			return $pid;
		}
	}
	return null;
}

function csfm_alias_in_use($name) {
	$needle = '/(^|[\s,"])' . preg_quote($name, '/') . '($|[\s,"])/';
	foreach (array('filter/rule', 'nat/rule', 'nat/outbound/rule', 'aliases/alias') as $path) {
		foreach ((array)csfm_cfg_get($path, array()) as $item) {
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

function csfm_apply_aliases($pid, $content, $prev, $state) {
	$aliases = array_values((array)csfm_cfg_get('aliases/alias', array()));
	$index = array();
	foreach ($aliases as $i => $a) {
		$index[$a['name']] = $i;
	}
	$adopt = !empty($content['adopt_existing']);
	$names = array();
	foreach ($content['aliases'] as $a) {
		$name = $a['name'];
		if (!preg_match('/^[A-Za-z0-9_]{1,31}$/', $name)) {
			throw new CsfmPolicyError("Invalid alias name '{$name}'");
		}
		$owner = csfm_alias_owner($name, $state, $pid);
		if ($owner !== null) {
			throw new CsfmPolicyError("Alias {$name} is already managed by policy {$owner}");
		}
		if (isset($index[$name]) && !$adopt && !in_array($name, $prev['items'] ?? array(), true)) {
			throw new CsfmPolicyError("Alias {$name} already exists on this firewall. Rename it or set adopt_existing.");
		}
		$entry = array(
			'name' => $name,
			'type' => $a['type'],
			'address' => implode(' ', $a['address'] ?? array()),
			'descr' => $a['descr'] ?? 'Managed by ComSense',
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
			if (csfm_alias_in_use($old)) {
				csfm_log("Keeping alias {$old}: still referenced by rules", LOG_WARNING);
				continue;
			}
			$aliases = array_values(array_filter($aliases, function ($a) use ($old) {
				return $a['name'] !== $old;
			}));
			$removed[] = $old;
		}
	}
	usort($aliases, function ($a, $b) { return strnatcasecmp($a['name'], $b['name']); });
	csfm_cfg_set('aliases/alias', $aliases);
	write_config("ComSense: applied alias policy {$pid}");
	csfm_reload(array('filter'));
	return array(
		'items' => $names,
		'summary' => sprintf('Set %d alias(es); removed %d', count($names), count($removed)),
	);
}

function csfm_remove_aliases($pid, $prev, $state) {
	$aliases = (array)csfm_cfg_get('aliases/alias', array());
	$removed = 0;
	$kept = array();
	foreach ($prev['items'] ?? array() as $name) {
		if (csfm_alias_in_use($name)) {
			$kept[] = $name;
			continue;
		}
		$aliases = array_filter($aliases, function ($a) use ($name) { return $a['name'] !== $name; });
		$removed++;
	}
	csfm_cfg_set('aliases/alias', array_values($aliases));
	write_config("ComSense: removed alias policy {$pid}");
	csfm_reload(array('filter'));
	$msg = "Removed {$removed} alias(es)";
	if ($kept) {
		$msg .= '; kept ' . implode(', ', $kept) . ' because rules still reference them';
	}
	return $msg;
}

/* ---------------------------------------------------------------- firewall rules */

function csfm_rule_endpoint($ep) {
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

function csfm_build_rule($pid, $r, $tracker) {
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
		'source' => csfm_rule_endpoint($r['source'] ?? array('any' => true)),
		'destination' => csfm_rule_endpoint($r['destination'] ?? array('any' => true)),
		'descr' => CSFM_RULE_PREFIX . ($r['descr'] ?? ''),
		'comsense_policy' => $pid,
		'created' => array('time' => (string)time(), 'username' => 'ComSense'),
		'updated' => array('time' => (string)time(), 'username' => 'ComSense'),
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

function csfm_is_policy_rule($rule, $pid) {
	return (string)($rule['comsense_policy'] ?? '') === (string)$pid;
}

function csfm_apply_rules($pid, $content, $prev) {
	$rules = array_values(array_filter((array)csfm_cfg_get('filter/rule', array()), function ($r) use ($pid) {
		return !csfm_is_policy_rule($r, $pid);
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
		$built = csfm_build_rule($pid, $r, $tracker);
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
	csfm_cfg_set('filter/rule', $rules);
	write_config("ComSense: applied firewall rule policy {$pid}");
	csfm_reload(array('filter'));
	return array('items' => array(), 'summary' => sprintf('Installed %d rule(s)', count($content['rules'])));
}

function csfm_remove_rules($pid) {
	$all = (array)csfm_cfg_get('filter/rule', array());
	$rules = array_values(array_filter($all, function ($r) use ($pid) {
		return !csfm_is_policy_rule($r, $pid);
	}));
	csfm_cfg_set('filter/rule', $rules);
	write_config("ComSense: removed firewall rule policy {$pid}");
	csfm_reload(array('filter'));
	return sprintf('Removed %d rule(s)', count($all) - count($rules));
}

/* ------------------------------------------------- port forwards (inbound NAT) */

/*
 * Identifies one port forward across the server and the firewall (the server computes the same from
 * config.xml): interface, protocol, target, local port, external port and description.
 */
function csfm_nat_fingerprint($nat) {
	$parts = array(
		(string)($nat['interface'] ?? ''), (string)($nat['protocol'] ?? ''), (string)($nat['target'] ?? ''),
		(string)($nat['local-port'] ?? ''), (string)($nat['destination']['port'] ?? ''), (string)($nat['descr'] ?? ''),
	);
	return substr(hash('sha256', implode("\x1f", $parts)), 0, 16);
}

/* One port forward added from the firewall's page (not owned by a configuration). */
function csfm_add_port_forward($r) {
	$nat = csfm_build_port_forward('', $r);
	unset($nat['comsense_policy']);
	$nat['descr'] = (string)($r['descr'] ?? '');
	$rules = array_values((array)csfm_cfg_get('nat/rule', array()));
	$fp = csfm_nat_fingerprint($nat);
	foreach ($rules as $existing) {
		if (csfm_nat_fingerprint($existing) === $fp) {
			return 'An identical port forward already exists';
		}
	}
	$rules[] = $nat;
	csfm_cfg_set('nat/rule', $rules);
	write_config('ComSense: added port forward ' . $nat['descr']);
	csfm_reload(array('filter'));
	return sprintf('Added port forward %s -> %s:%s', $nat['destination']['port'] ?? '', $nat['target'], $nat['local-port']);
}

/* Remove one port forward by fingerprint, with its linked filter rule. Configuration-owned ones are refused. */
function csfm_remove_port_forward($fingerprint) {
	$rules = array_values((array)csfm_cfg_get('nat/rule', array()));
	foreach ($rules as $i => $nat) {
		if (csfm_nat_fingerprint($nat) !== $fingerprint) {
			continue;
		}
		if (!empty($nat['comsense_policy'])) {
			throw new CsfmPolicyError('This port forward belongs to a ComSense configuration; unassign that instead');
		}
		array_splice($rules, $i, 1);
		csfm_cfg_set('nat/rule', $rules);
		$assoc = (string)($nat['associated-rule-id'] ?? '');
		$removedRule = 0;
		if ($assoc !== '' && $assoc !== 'pass') {
			$filters = (array)csfm_cfg_get('filter/rule', array());
			$kept = array_values(array_filter($filters, function ($f) use ($assoc) {
				return (string)($f['associated-rule-id'] ?? '') !== $assoc;
			}));
			$removedRule = count($filters) - count($kept);
			csfm_cfg_set('filter/rule', $kept);
		}
		write_config('ComSense: removed port forward ' . ($nat['descr'] ?? ''));
		csfm_reload(array('filter'));
		return 'Removed port forward ' . ($nat['descr'] ?? '') . ($removedRule ? ' and its linked firewall rule' : '');
	}
	throw new CsfmPolicyError('That port forward is no longer on the firewall');
}

/* ------------------------------------------------- pfSense email notifications */

/* Whether pfSense sends its own email notifications (System > Advanced > Notifications). */
function csfm_set_smtp_notifications($enabled) {
	if ($enabled) {
		csfm_cfg_del('notifications/smtp/disable');
	} else {
		csfm_cfg_set('notifications/smtp/disable', true);
	}
	write_config('ComSense: ' . ($enabled ? 'enabled' : 'disabled') . ' email notifications');
	return $enabled ? 'Email notifications turned on' : 'Email notifications turned off';
}

function csfm_apply_notifications($content, $prev) {
	$saved = $prev['saved'] ?? array();
	csfm_remember($saved, 'notifications/smtp/disable');
	$summary = csfm_set_smtp_notifications(!empty($content['smtp']));
	return array('items' => array(), 'saved' => $saved, 'summary' => $summary);
}

function csfm_build_port_forward($pid, $r) {
	$nat = array(
		'source' => csfm_rule_endpoint($r['source'] ?? array('any' => true)),
		'destination' => csfm_rule_endpoint($r['destination'] ?? array('network' => 'wanip')),
		'ipprotocol' => $r['ipprotocol'] ?? 'inet',
		'protocol' => $r['protocol'] ?? 'tcp',
		'target' => (string)$r['target'],
		'local-port' => (string)$r['local_port'],
		'interface' => $r['interface'] ?? 'wan',
		'descr' => CSFM_RULE_PREFIX . ($r['descr'] ?? ''),
		/* "Pass": the port forward lets its own traffic through; no separate filter rule to manage. */
		'associated-rule-id' => 'pass',
		'comsense_policy' => $pid,
		'created' => array('time' => (string)time(), 'username' => 'ComSense'),
		'updated' => array('time' => (string)time(), 'username' => 'ComSense'),
	);
	if (!empty($r['disabled'])) {
		$nat['disabled'] = '';
	}
	return $nat;
}

function csfm_apply_port_forwards($pid, $content) {
	$others = array_values(array_filter((array)csfm_cfg_get('nat/rule', array()), function ($r) use ($pid) {
		return !csfm_is_policy_rule($r, $pid);
	}));
	$new = array();
	foreach ($content['rules'] as $r) {
		$new[] = csfm_build_port_forward($pid, $r);
	}
	$all = (($content['position'] ?? 'top') === 'bottom') ? array_merge($others, $new) : array_merge($new, $others);
	csfm_cfg_set('nat/rule', $all);
	write_config("ComSense: applied port forward policy {$pid}");
	csfm_reload(array('filter'));
	return array('items' => array(), 'summary' => sprintf('Installed %d port forward(s)', count($new)));
}

function csfm_remove_port_forwards($pid) {
	$all = (array)csfm_cfg_get('nat/rule', array());
	$kept = array_values(array_filter($all, function ($r) use ($pid) {
		return !csfm_is_policy_rule($r, $pid);
	}));
	csfm_cfg_set('nat/rule', $kept);
	write_config("ComSense: removed port forward policy {$pid}");
	csfm_reload(array('filter'));
	return sprintf('Removed %d port forward(s)', count($all) - count($kept));
}

/* ------------------------------------------------- system and config_set policies */

/* Remember the original value of a path the first time a policy changes it. */
function csfm_remember(&$saved, $path) {
	if (!array_key_exists($path, $saved)) {
		$value = csfm_cfg_get($path, null);
		$saved[$path] = array('present' => $value !== null, 'value' => $value);
	}
}

function csfm_restore_saved_values($prev, $message) {
	foreach ($prev['saved'] ?? array() as $path => $orig) {
		if (!empty($orig['present'])) {
			csfm_cfg_set($path, $orig['value']);
		} else {
			csfm_cfg_del($path);
		}
	}
	write_config($message);
	csfm_reload(array_merge(array('filter', 'dns', 'ntp', 'hostname'), $prev['reload'] ?? array()));
	return sprintf('Restored %d setting(s) to their previous values', count($prev['saved'] ?? array()));
}

function csfm_apply_system($pid, $content, $prev) {
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
			csfm_remember($saved, $path);
			csfm_cfg_set($path, (string)$content[$key]);
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
		csfm_remember($saved, 'system/dnsserver');
		foreach ($content['dnsservers'] as $ip) {
			if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
				throw new CsfmPolicyError("Invalid DNS server '{$ip}'");
			}
		}
		csfm_cfg_set('system/dnsserver', array_values($content['dnsservers']));
		$reload[] = 'dns';
	}
	if (array_key_exists('dnsallowoverride', $content)) {
		csfm_remember($saved, 'system/dnsallowoverride');
		if ($content['dnsallowoverride']) {
			csfm_cfg_set('system/dnsallowoverride', '');
		} else {
			csfm_cfg_del('system/dnsallowoverride');
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
			!empty($orig['present']) ? csfm_cfg_set($path, $orig['value']) : csfm_cfg_del($path);
			unset($saved[$path]);
			$reload = array_merge($reload, array('dns', 'ntp', 'hostname'));
		}
	}
	write_config("ComSense: applied system policy {$pid}");
	csfm_reload(array_merge($reload, array('filter')));
	return array('items' => array(), 'saved' => $saved, 'summary' => 'System settings applied');
}

function csfm_path_protected($path) {
	global $csfm_protected_paths;
	foreach ($csfm_protected_paths as $p) {
		if ($path === $p || strpos($path, $p . '/') === 0) {
			return true;
		}
	}
	return false;
}

function csfm_apply_config_set($pid, $content, $prev) {
	$saved = $prev['saved'] ?? array();
	$touched = array();
	foreach ($content['items'] as $item) {
		$path = (string)$item['path'];
		if (!preg_match('#^[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-]+)*$#', $path) || csfm_path_protected($path)) {
			throw new CsfmPolicyError("Path '{$path}' is not allowed");
		}
		csfm_remember($saved, $path);
		if (!empty($item['delete'])) {
			csfm_cfg_del($path);
		} else {
			csfm_cfg_set($path, $item['value']);
		}
		$touched[] = $path;
	}
	foreach (array_keys($saved) as $path) {
		if (!in_array($path, $touched, true)) {
			$orig = $saved[$path];
			!empty($orig['present']) ? csfm_cfg_set($path, $orig['value']) : csfm_cfg_del($path);
			unset($saved[$path]);
		}
	}
	$reload = array_values(array_intersect((array)($content['reload'] ?? array()),
	    array('filter', 'dns', 'ntp', 'webgui', 'hostname', 'routing', 'unbound', 'dnsmasq')));
	write_config("ComSense: applied config policy {$pid}");
	csfm_reload($reload);
	return array(
		'items' => array(),
		'saved' => $saved,
		'reload' => $reload,
		'summary' => sprintf('Set %d config value(s)', count($touched)),
	);
}

/* ---------------------------------------------------------------- packages */

function csfm_pkg_installed($name) {
	exec(CSFM_PKG . ' info -e ' . escapeshellarg($name), $out, $rc);
	return $rc === 0;
}

function csfm_apply_packages($pid, $content, $prev) {
	$log = array();
	foreach ((array)($content['install'] ?? array()) as $name) {
		if (!preg_match('/^pfSense-pkg-[A-Za-z0-9_.+-]{1,64}$/', $name)) {
			throw new CsfmPolicyError("Invalid package name '{$name}'");
		}
		if (csfm_pkg_installed($name)) {
			continue;
		}
		list($rc, $out) = csfm_exec('/usr/local/sbin/pfSense-upgrade -y -i ' . escapeshellarg($name), 1200);
		$log[] = "install {$name}: rc={$rc}";
		if ($rc !== 0) {
			throw new CsfmPolicyError("Installing {$name} failed:\n" . csfm_truncate($out, 4000));
		}
	}
	foreach ((array)($content['remove'] ?? array()) as $name) {
		if (!preg_match('/^pfSense-pkg-[A-Za-z0-9_.+-]{1,64}$/', $name) || $name === 'pfSense-pkg-ComSense') {
			throw new CsfmPolicyError("Refusing to remove '{$name}'");
		}
		if (!csfm_pkg_installed($name)) {
			continue;
		}
		list($rc, $out) = csfm_exec('/usr/local/sbin/pfSense-upgrade -y -r ' . escapeshellarg($name), 1200);
		$log[] = "remove {$name}: rc={$rc}";
		if ($rc !== 0) {
			throw new CsfmPolicyError("Removing {$name} failed:\n" . csfm_truncate($out, 4000));
		}
	}
	return array('items' => array(), 'summary' => $log ? implode("\n", $log) : 'All packages already in the desired state');
}
