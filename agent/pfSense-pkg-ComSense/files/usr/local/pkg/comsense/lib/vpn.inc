<?php
/*
 * ComSense agent - VPN status (IPsec, OpenVPN, WireGuard) and connect / disconnect / reconnect.
 *
 * Status comes from the VPN's own tools, read every check-in:
 *   IPsec      swanctl --list-sas (strongSwan), matched to ipsec/phase1 and phase2 in config.xml
 *   OpenVPN    openvpn_get_active_servers() / openvpn_get_active_clients() (pfSense's openvpn.inc, which
 *              asks each instance's management socket)
 *   WireGuard  wg show all dump, matched to the WireGuard package's tunnels and peers
 *
 * A tunnel that is down carries "since": when the agent first saw it down (kept across check-ins), so the
 * server alerts only on tunnels that stay down, not on a rekey or a restart in progress.
 *
 * Connecting and disconnecting are temporary: a tunnel set to start by itself comes back on its own, and
 * a reboot restores everything. To keep a tunnel down, disable it in pfSense.
 */

require_once(__DIR__ . '/common.inc');

if (!defined('CSFM_SWANCTL')) {
	define('CSFM_SWANCTL', '/usr/local/sbin/swanctl');
}
if (!defined('CSFM_WG')) {
	define('CSFM_WG', '/usr/local/bin/wg');
}
if (!defined('CSFM_IFCONFIG')) {
	define('CSFM_IFCONFIG', '/sbin/ifconfig');
}
if (!defined('CSFM_OPENVPN_BASE')) {
	define('CSFM_OPENVPN_BASE', '/var/etc/openvpn');
}
/* Seconds to let a tunnel settle after connecting before reporting how it looks. */
if (!defined('CSFM_VPN_SETTLE')) {
	define('CSFM_VPN_SETTLE', 6);
}
/* A WireGuard peer is connected while its last handshake is this recent (WireGuard rekeys every 2 minutes). */
define('CSFM_WG_HANDSHAKE_FRESH', 180);
define('CSFM_VPN_MAX', 200);  /* entries per kind in the report */

function csfm_vpn_list($path) {
	$v = csfm_cfg_get($path, array());
	if (!is_array($v)) {
		return array();
	}
	/* One entry comes back as the entry itself, several as a list. */
	return array_key_exists(0, $v) || !$v ? $v : array($v);
}

function csfm_vpn_enabled($item) {
	return is_array($item) && !isset($item['disabled']);
}

/* ------------------------------------------------------------------ IPsec */

/*
 * swanctl --list-sas, plain output:
 *   con1: #3, ESTABLISHED, IKEv2, 1a2b...
 *     local  'a' @ 198.51.100.2[4500]
 *     remote 'b' @ 203.0.113.9[4500]
 *     established 1234s ago, rekeying in 25000s
 *     con1_1: #10, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256
 *       installed 600s ago, rekeying in 2500s, expires in 3000s
 *       in  c1234567,  12345 bytes,   100 packets,     5s ago
 *       out c7654321,  54321 bytes,   120 packets,     5s ago
 * Returns {ike name: {state, remote, established, children: {name: {state, bytes_in, bytes_out}}}}.
 */
function csfm_parse_swanctl_sas($text) {
	$sas = array();
	$ike = null;
	$child = null;
	foreach (preg_split('/\r?\n/', (string)$text) as $line) {
		if (preg_match('/^([^\s:][^:]*): #\d+, ([A-Z_]+),/', $line, $m)) {
			$ike = $m[1];
			$child = null;
			$cur = $sas[$ike] ?? array('state' => '', 'remote' => '', 'established' => null, 'children' => array(),
			    'count' => 0);
			$cur['count']++;  /* mobile clients each have their own IKE SA under one name */
			/* Several IKE SAs of one connection (a rekey in progress): the established one wins. */
			if ($cur['state'] !== 'ESTABLISHED') {
				$cur['state'] = $m[2];
			}
			$sas[$ike] = $cur;
		} elseif ($ike !== null && preg_match('/^\s{2}([^\s:][^:]*): #\d+,.*?\b(INSTALLED|INSTALLING|REKEYING|REKEYED|DELETING|CREATED|ROUTED|DESTROYING)\b/', $line, $m)) {
			$child = $m[1];
			if (!isset($sas[$ike]['children'][$child]) || $m[2] === 'INSTALLED') {
				$sas[$ike]['children'][$child] = array('state' => $m[2], 'bytes_in' => 0, 'bytes_out' => 0);
			}
		} elseif ($ike !== null && $child === null && preg_match('/^\s{2}remote\s.*@ ([^\[\s]+)/', $line, $m)) {
			$sas[$ike]['remote'] = $m[1];
		} elseif ($ike !== null && $child === null && preg_match('/^\s{2}established (\d+)s ago/', $line, $m)) {
			$sas[$ike]['established'] = (int)$m[1];
		} elseif ($child !== null && preg_match('/^\s{4}(in|out)\s+\S+,\s+(\d+) bytes/', $line, $m)) {
			$sas[$ike]['children'][$child]['bytes_' . $m[1]] += (int)$m[2];
		}
	}
	return $sas;
}

function csfm_ipsec_sas() {
	if (!is_executable(CSFM_SWANCTL)) {
		return null;
	}
	list($rc, $out) = csfm_exec(escapeshellarg(CSFM_SWANCTL) . ' --list-sas --noblock', 20);
	return $rc === 0 ? csfm_parse_swanctl_sas($out) : null;
}

function csfm_collect_ipsec() {
	$phase1 = array_filter(csfm_vpn_list('ipsec/phase1'), 'csfm_vpn_enabled');
	if (!$phase1) {
		return array();
	}
	$p2s = array();
	foreach (csfm_vpn_list('ipsec/phase2') as $p2) {
		if (csfm_vpn_enabled($p2) && isset($p2['ikeid'])) {
			$p2s[(string)$p2['ikeid']][] = $p2;
		}
	}
	$sas = csfm_ipsec_sas();
	$out = array();
	foreach ($phase1 as $p1) {
		$ikeid = (string)($p1['ikeid'] ?? '');
		if ($ikeid === '') {
			continue;
		}
		$mobile = isset($p1['mobile']);
		$entry = array(
			'id' => $ikeid,
			'name' => (string)($p1['descr'] ?? '') ?: "Tunnel {$ikeid}",
			'remote' => $mobile ? 'mobile clients' : (string)($p1['remote-gateway'] ?? ''),
			'mobile' => $mobile,
			/* Waits for the other side to connect, so being down is not a fault here. */
			'responder' => in_array((string)($p1['startaction'] ?? ''), array('none'), true)
			    || isset($p1['responderonly']),
			'children_expected' => csfm_ipsec_expected_children($p1, $p2s[$ikeid] ?? array()),
		);
		if ($sas === null) {
			$entry['status'] = 'unknown';
		} else {
			$state = '';
			$installed = 0;
			$in = $outb = 0;
			$established = null;
			$remote = '';
			$mobile_up = 0;
			foreach ($sas as $name => $sa) {
				/* con1, and with pfSense 2.5+ also con1 children con1_100 etc.; mobile SAs are con-mobile... */
				if (!csfm_ipsec_name_matches($name, $ikeid, $mobile)) {
					continue;
				}
				$mobile_up += (int)($sa['count'] ?? 1);
				if ($sa['state'] === 'ESTABLISHED' || $state === '') {
					$state = $sa['state'];
				}
				$established = $sa['established'] ?? $established;
				$remote = $sa['remote'] ?: $remote;
				foreach ($sa['children'] as $c) {
					if ($c['state'] === 'INSTALLED') {
						$installed++;
					}
					$in += $c['bytes_in'];
					$outb += $c['bytes_out'];
				}
			}
			$expected = max(1, $entry['children_expected']);
			if ($state === 'ESTABLISHED' && $installed >= $expected) {
				$entry['status'] = 'up';
			} elseif ($state === 'ESTABLISHED') {
				$entry['status'] = $installed > 0 ? 'partial' : 'down';
			} else {
				$entry['status'] = 'down';
			}
			if ($mobile) {
				$entry['status'] = $mobile_up > 0 ? 'up' : 'idle';
				$entry['clients'] = $mobile_up;
			}
			$entry['children_up'] = $installed;
			$entry['connected_for'] = $established;
			$entry['remote_address'] = $remote;
			$entry['bytes_in'] = $in;
			$entry['bytes_out'] = $outb;
		}
		$out[] = $entry;
		if (count($out) >= CSFM_VPN_MAX) {
			break;
		}
	}
	return $out;
}

/* swanctl names a phase 1 "con<ikeid>" (split connections "con<ikeid>_<n>"), mobile clients "con-mobile". */
function csfm_ipsec_name_matches($name, $ikeid, $mobile = false) {
	return (bool)preg_match('/^con' . preg_quote($ikeid, '/') . '(?:$|[^0-9])/', $name)
	    || ($mobile && strpos($name, 'con-mobile') === 0);
}

/*
 * How many child SAs a working tunnel has. IKEv2 puts every phase 2 into one child unless "Split
 * connections" is on; IKEv1, split connections and VTI phase 2s get one each.
 */
function csfm_ipsec_expected_children($p1, $p2s) {
	if (!$p2s) {
		return 0;
	}
	$vti = count(array_filter($p2s, function ($p) { return ($p['mode'] ?? '') === 'vti'; }));
	$other = count($p2s) - $vti;
	if (($p1['iketype'] ?? 'ikev2') === 'ikev2' && !isset($p1['splitconn'])) {
		return $vti + ($other > 0 ? 1 : 0);
	}
	return count($p2s);
}

/* swanctl --list-conns: the child names of connection conN (indented two spaces, "name: TUNNEL, ..."). */
function csfm_ipsec_children($ikeid) {
	list($rc, $out) = csfm_exec(escapeshellarg(CSFM_SWANCTL) . ' --list-conns', 20);
	$names = array();
	$in = false;
	foreach (preg_split('/\r?\n/', (string)$out) as $line) {
		if (preg_match('/^([^\s:][^:]*):/', $line, $m)) {
			$in = csfm_ipsec_name_matches($m[1], $ikeid);
		} elseif ($in && preg_match('/^\s{2}([^\s:][^:]*): (TUNNEL|TRANSPORT|BEET)/', $line, $m)) {
			$names[] = $m[1];
		}
	}
	return $names;
}

function csfm_ipsec_control($id, $action) {
	if (!preg_match('/^\d+$/', $id)) {
		throw new Exception('Unknown IPsec tunnel');
	}
	$found = false;
	foreach (csfm_vpn_list('ipsec/phase1') as $p1) {
		if ((string)($p1['ikeid'] ?? '') === $id) {
			if (!csfm_vpn_enabled($p1)) {
				throw new Exception('This IPsec tunnel is disabled in pfSense; enable it there first.');
			}
			if (isset($p1['mobile'])) {
				throw new Exception('Mobile client connections are started by the clients, not the firewall.');
			}
			$found = true;
		}
	}
	if (!$found) {
		throw new Exception("No IPsec tunnel {$id} on this firewall");
	}
	if (!is_executable(CSFM_SWANCTL)) {
		throw new Exception('IPsec is not running on this firewall (swanctl is missing).');
	}
	$conn = "con{$id}";
	$log = array();
	if ($action === 'disconnect' || $action === 'reconnect') {
		$names = array_values(array_filter(array_keys(csfm_ipsec_sas() ?? array()),
		    function ($n) use ($id) { return csfm_ipsec_name_matches($n, $id); }));
		if (!$names) {
			$log[] = 'It was not connected.';
		}
		foreach ($names as $name) {
			list($rc, $out) = csfm_exec(escapeshellarg(CSFM_SWANCTL) . ' --terminate --ike ' . escapeshellarg($name)
			    . ' --timeout 15', 30);
			$lines = array_filter(preg_split('/\r?\n/', trim($out)));
			$log[] = ($lines ? end($lines) : '') ?: "terminate {$name}: exit {$rc}";
		}
	}
	if ($action === 'connect' || $action === 'reconnect') {
		if ($action === 'reconnect') {
			sleep(2);
		}
		$children = csfm_ipsec_children($id);
		$targets = $children ? array_map(function ($c) { return '--child ' . escapeshellarg($c); }, $children)
		    : array('--ike ' . escapeshellarg($conn));
		foreach ($targets as $t) {
			list($rc, $out) = csfm_exec(escapeshellarg(CSFM_SWANCTL) . ' --initiate ' . $t . ' --timeout 20', 35);
			$lines = array_filter(preg_split('/\r?\n/', trim($out)));
			$log[] = ($lines ? end($lines) : '') ?: "initiate: exit {$rc}";
		}
	}
	return $log;
}

/* ------------------------------------------------------------------ OpenVPN */

function csfm_openvpn_load() {
	if (!function_exists('openvpn_get_active_servers')) {
		@include_once('openvpn.inc');
	}
	return function_exists('openvpn_get_active_servers') && function_exists('openvpn_get_active_clients');
}

function csfm_collect_openvpn() {
	$servers = array_filter(csfm_vpn_list('openvpn/openvpn-server'), 'csfm_vpn_enabled');
	$clients = array_filter(csfm_vpn_list('openvpn/openvpn-client'), 'csfm_vpn_enabled');
	if (!$servers && !$clients) {
		return array();
	}
	$out = array();
	$descr = array();
	foreach (array('server' => $servers, 'client' => $clients) as $mode => $list) {
		foreach ($list as $c) {
			$descr[$mode][(string)($c['vpnid'] ?? '')] = $c;
		}
	}
	if (!csfm_openvpn_load()) {
		foreach ($descr as $mode => $list) {
			foreach ($list as $vpnid => $c) {
				$out[] = array('id' => "{$mode}:{$vpnid}", 'mode' => $mode, 'vpnid' => (string)$vpnid,
				    'name' => (string)($c['description'] ?? '') ?: "OpenVPN {$mode} {$vpnid}", 'status' => 'unknown');
			}
		}
		return $out;
	}
	$seen = array();
	$active = array();
	foreach (array('multipoint', 'p2p') as $type) {
		try {
			foreach ((array)openvpn_get_active_servers($type) as $s) {
				$active[] = array($type, $s);
			}
		} catch (Throwable $e) {
			csfm_log('OpenVPN server status unavailable: ' . $e->getMessage(), LOG_WARNING);
		}
	}
	foreach ($active as list($type, $s)) {
		$vpnid = (string)($s['vpnid'] ?? '');
		if ($vpnid === '' || isset($seen["server:{$vpnid}"])) {
			continue;
		}
		$seen["server:{$vpnid}"] = true;
		$cfg = $descr['server'][$vpnid] ?? array();
		$entry = array(
			'id' => "server:{$vpnid}",
			'mode' => 'server',
			'vpnid' => $vpnid,
			'name' => (string)($cfg['description'] ?? '') ?: (string)($s['name'] ?? "OpenVPN server {$vpnid}"),
			'remote' => '',
			'p2p' => $type === 'p2p',
		);
		if ($type === 'p2p') {
			$status = strtolower((string)($s['status'] ?? ''));
			$entry['status'] = $status === 'up' ? 'up' : ($status === '' ? 'unknown' : 'down');
			$entry['detail'] = (string)($s['state_detail'] ?? $s['status'] ?? '');
			$entry['remote_address'] = (string)($s['remote_host'] ?? '');
			$entry['connected_since'] = (string)($s['connect_time'] ?? '');
		} else {
			$conns = array();
			foreach ((array)($s['conns'] ?? array()) as $c) {
				if (!is_array($c) || ($c['common_name'] ?? '') === '[error]') {
					continue;
				}
				$conns[] = array(
					'user' => (string)($c['common_name'] ?? $c['user_name'] ?? ''),
					'remote' => (string)($c['remote_host'] ?? ''),
					'address' => (string)($c['virtual_addr'] ?? ''),
					'since' => (string)($c['connect_time'] ?? ''),
					'client_id' => (string)($c['client_id'] ?? ''),
					'bytes_in' => csfm_num($c['bytes_recv'] ?? 0),
					'bytes_out' => csfm_num($c['bytes_sent'] ?? 0),
				);
			}
			$entry['status'] = 'up';
			$entry['clients'] = count($conns);
			$entry['connections'] = array_slice($conns, 0, CSFM_VPN_MAX);
		}
		$out[] = $entry;
	}
	/* Servers whose process is not running do not answer at all. */
	foreach ($descr['server'] ?? array() as $vpnid => $cfg) {
		if (!isset($seen["server:{$vpnid}"])) {
			$out[] = array('id' => "server:{$vpnid}", 'mode' => 'server', 'vpnid' => (string)$vpnid,
			    'name' => (string)($cfg['description'] ?? '') ?: "OpenVPN server {$vpnid}", 'status' => 'down',
			    'p2p' => strpos((string)($cfg['mode'] ?? ''), 'p2p') === 0, 'detail' => 'not running');
		}
	}
	try {
		$clientStatus = (array)openvpn_get_active_clients();
	} catch (Throwable $e) {
		$clientStatus = array();
		csfm_log('OpenVPN client status unavailable: ' . $e->getMessage(), LOG_WARNING);
	}
	foreach ($clientStatus as $c) {
		$vpnid = (string)($c['vpnid'] ?? '');
		if ($vpnid === '' || isset($seen["client:{$vpnid}"])) {
			continue;
		}
		$seen["client:{$vpnid}"] = true;
		$cfg = $descr['client'][$vpnid] ?? array();
		$status = strtolower((string)($c['status'] ?? ''));
		$out[] = array(
			'id' => "client:{$vpnid}",
			'mode' => 'client',
			'vpnid' => $vpnid,
			'name' => (string)($cfg['description'] ?? '') ?: (string)($c['name'] ?? "OpenVPN client {$vpnid}"),
			'remote' => trim((string)($cfg['server_addr'] ?? '') . ':' . (string)($cfg['server_port'] ?? ''), ':'),
			'status' => $status === 'up' ? 'up' : 'down',
			'detail' => (string)($c['state_detail'] ?? '') ?: (string)($c['status'] ?? ''),
			'remote_address' => (string)($c['remote_host'] ?? ''),
			'address' => (string)($c['virtual_addr'] ?? ''),
			'connected_since' => (string)($c['connect_time'] ?? ''),
		);
	}
	foreach ($descr['client'] ?? array() as $vpnid => $cfg) {
		if (!isset($seen["client:{$vpnid}"])) {
			$out[] = array('id' => "client:{$vpnid}", 'mode' => 'client', 'vpnid' => (string)$vpnid,
			    'name' => (string)($cfg['description'] ?? '') ?: "OpenVPN client {$vpnid}",
			    'remote' => trim((string)($cfg['server_addr'] ?? '') . ':' . (string)($cfg['server_port'] ?? ''), ':'),
			    'status' => 'down', 'detail' => 'not running');
		}
	}
	return array_slice($out, 0, CSFM_VPN_MAX);
}

/* Disconnect one remote user from an OpenVPN server through its management socket. */
function csfm_openvpn_kick($vpnid, $client) {
	$sock = CSFM_OPENVPN_BASE . "/server{$vpnid}/sock";
	$fp = @stream_socket_client("unix://{$sock}", $errno, $errstr, 5);
	if (!$fp) {
		throw new Exception("Could not reach the OpenVPN server's management socket: {$errstr}");
	}
	stream_set_timeout($fp, 5);
	$cmd = preg_match('/^\d+$/', $client) ? "client-kill {$client}" : "kill {$client}";
	fwrite($fp, "{$cmd}\n");
	$reply = '';
	while (!feof($fp)) {
		$line = fgets($fp, 1024);
		if ($line === false) {
			break;
		}
		if (strpos($line, '>INFO') === 0) {
			continue;
		}
		$reply = trim($line);
		if (strpos($reply, 'SUCCESS') === 0 || strpos($reply, 'ERROR') === 0) {
			break;
		}
	}
	fwrite($fp, "quit\n");
	fclose($fp);
	if (strpos($reply, 'SUCCESS') !== 0) {
		throw new Exception('OpenVPN refused: ' . ($reply ?: 'no answer'));
	}
	return $reply;
}

function csfm_openvpn_control($id, $action, $payload) {
	if (!preg_match('/^(server|client):(\d+)$/', $id, $m)) {
		throw new Exception('Unknown OpenVPN instance');
	}
	list(, $mode, $vpnid) = $m;
	$cfg = null;
	foreach (csfm_vpn_list("openvpn/openvpn-{$mode}") as $c) {
		if ((string)($c['vpnid'] ?? '') === $vpnid) {
			$cfg = $c;
		}
	}
	if ($cfg === null) {
		throw new Exception("No OpenVPN {$mode} {$vpnid} on this firewall");
	}
	if (!csfm_vpn_enabled($cfg)) {
		throw new Exception("This OpenVPN {$mode} is disabled in pfSense; enable it there first.");
	}
	if ($action === 'kick') {
		$who = (string)($payload['client'] ?? '');
		if ($mode !== 'server' || !preg_match('/^(\d+|[0-9a-fA-F:.\[\]]+:\d+)$/', $who)) {
			throw new Exception('Say which connected user to disconnect');
		}
		return array('Disconnected ' . (string)($payload['user'] ?? $who) . ': ' . csfm_openvpn_kick($vpnid, $who));
	}
	$extras = array('vpnmode' => $mode, 'id' => $vpnid);
	$fn = array('connect' => 'service_control_start', 'disconnect' => 'service_control_stop',
	    'reconnect' => 'service_control_restart')[$action];
	if (!function_exists($fn)) {
		throw new Exception('Service control is not available');
	}
	return array(trim((string)$fn('openvpn', $extras)) ?: "OpenVPN {$mode} {$vpnid}: {$action} done");
}

/* ------------------------------------------------------------------ WireGuard */

/*
 * wg show all dump: interface lines have 5 fields (name, private key, public key, port, fwmark), peer
 * lines 9 (name, public key, preshared key, endpoint, allowed ips, latest handshake, rx, tx, keepalive).
 * Keys other than the peers' public keys are never kept.
 */
function csfm_parse_wg_dump($text) {
	$peers = array();
	foreach (preg_split('/\r?\n/', (string)$text) as $line) {
		$f = explode("\t", $line);
		if (count($f) !== 9) {
			continue;
		}
		$peers[$f[0]][$f[1]] = array(
			'endpoint' => $f[3] === '(none)' ? '' : $f[3],
			'handshake' => (int)$f[5],
			'rx' => csfm_num($f[6]),
			'tx' => csfm_num($f[7]),
			'keepalive' => $f[8] === 'off' ? 0 : (int)$f[8],
		);
	}
	return $peers;
}

function csfm_wg_interfaces_up() {
	list($rc, $out) = csfm_exec(escapeshellarg(CSFM_IFCONFIG) . ' -l -u', 10);
	return $rc === 0 ? preg_split('/\s+/', trim($out)) : null;
}

function csfm_collect_wireguard() {
	$tunnels = csfm_vpn_list('installedpackages/wireguard/tunnels/item');
	if (!$tunnels) {
		return array();
	}
	$peers_cfg = csfm_vpn_list('installedpackages/wireguard/peers/item');
	$live = null;
	if (is_executable(CSFM_WG)) {
		list($rc, $out) = csfm_exec(escapeshellarg(CSFM_WG) . ' show all dump', 15);
		$live = $rc === 0 ? csfm_parse_wg_dump($out) : null;
	}
	$up = csfm_wg_interfaces_up();
	$now = time();
	$out = array();
	foreach ($tunnels as $t) {
		$name = (string)($t['name'] ?? '');
		if ($name === '' || ($t['enabled'] ?? 'yes') !== 'yes') {
			continue;
		}
		$peers = array();
		foreach ($peers_cfg as $p) {
			if (($p['tun'] ?? '') !== $name || ($p['enabled'] ?? 'yes') !== 'yes') {
				continue;
			}
			$pub = (string)($p['publickey'] ?? '');
			$endpoint = trim((string)($p['endpoint'] ?? ''));
			$keepalive = (int)($p['persistentkeepalive'] ?? 0);
			$peer = array(
				'id' => substr(hash('sha256', $pub), 0, 12),
				'name' => (string)($p['descr'] ?? '') ?: substr($pub, 0, 8) . '…',
				'endpoint' => $endpoint === '' ? '' : $endpoint . ':' . ((string)($p['port'] ?? '') ?: '51820'),
				'keepalive' => $keepalive,
			);
			$l = $live[$name][$pub] ?? null;
			if ($live === null) {
				$peer['status'] = 'unknown';
			} else {
				$hs = $l ? (int)$l['handshake'] : 0;
				$age = $hs > 0 ? max(0, $now - $hs) : null;
				$peer['handshake_age'] = $age;
				$peer['bytes_in'] = $l['rx'] ?? 0;
				$peer['bytes_out'] = $l['tx'] ?? 0;
				$peer['remote_address'] = $l['endpoint'] ?? '';
				if ($age !== null && $age <= CSFM_WG_HANDSHAKE_FRESH + $keepalive) {
					$peer['status'] = 'up';
				} elseif ($endpoint !== '' && $keepalive > 0) {
					/* It keeps the tunnel alive itself, so no recent handshake means it cannot get through. */
					$peer['status'] = 'down';
				} else {
					/* Handshakes happen only when there is traffic: quiet is not down. */
					$peer['status'] = 'idle';
				}
			}
			$peers[] = $peer;
		}
		$ifup = $up === null ? null : in_array($name, $up, true);
		$statuses = array_column($peers, 'status');
		if ($ifup === false) {
			$status = 'down';
		} elseif (in_array('up', $statuses, true)) {
			$status = in_array('down', $statuses, true) ? 'partial' : 'up';
		} elseif (in_array('down', $statuses, true)) {
			$status = 'down';
		} else {
			$status = $live === null ? 'unknown' : 'idle';
		}
		$out[] = array(
			'id' => $name,
			'name' => (string)($t['descr'] ?? '') ?: $name,
			'interface' => $name,
			'interface_up' => $ifup,
			'port' => (string)($t['listenport'] ?? ''),
			'status' => $status,
			'peers' => array_slice($peers, 0, CSFM_VPN_MAX),
		);
	}
	return $out;
}

function csfm_wireguard_control($id, $action, $payload) {
	if (!preg_match('/^tun_wg\d+$/', $id)) {
		throw new Exception('Unknown WireGuard tunnel');
	}
	$tunnel = null;
	foreach (csfm_vpn_list('installedpackages/wireguard/tunnels/item') as $t) {
		if (($t['name'] ?? '') === $id) {
			$tunnel = $t;
		}
	}
	if ($tunnel === null) {
		throw new Exception("No WireGuard tunnel {$id} on this firewall");
	}
	if (($tunnel['enabled'] ?? 'yes') !== 'yes') {
		throw new Exception('This WireGuard tunnel is disabled in pfSense; enable it there first.');
	}
	$log = array();
	$ifc = function ($updown) use ($id, &$log) {
		list($rc, $out) = csfm_exec(escapeshellarg(CSFM_IFCONFIG) . ' ' . escapeshellarg($id) . ' ' . $updown, 15);
		if ($rc !== 0) {
			throw new Exception("ifconfig {$id} {$updown} failed: " . trim($out));
		}
		$log[] = "{$id} {$updown}";
	};
	if ($action === 'disconnect' || $action === 'reconnect') {
		$ifc('down');
	}
	if ($action === 'reconnect') {
		sleep(1);
	}
	if ($action === 'connect' || $action === 'reconnect') {
		$ifc('up');
		/* Setting a peer's endpoint again looks its name up again and starts a fresh handshake. */
		$only = (string)($payload['peer'] ?? '');
		foreach (csfm_vpn_list('installedpackages/wireguard/peers/item') as $p) {
			$pub = (string)($p['publickey'] ?? '');
			$endpoint = trim((string)($p['endpoint'] ?? ''));
			if (($p['tun'] ?? '') !== $id || $endpoint === '' || $pub === '' || ($p['enabled'] ?? 'yes') !== 'yes') {
				continue;
			}
			if ($only !== '' && substr(hash('sha256', $pub), 0, 12) !== $only) {
				continue;
			}
			$host = strpos($endpoint, ':') !== false && strpos($endpoint, '[') !== 0 ? "[{$endpoint}]" : $endpoint;
			$target = $host . ':' . ((string)($p['port'] ?? '') ?: '51820');
			list($rc, $out) = csfm_exec(escapeshellarg(CSFM_WG) . ' set ' . escapeshellarg($id) . ' peer '
			    . escapeshellarg($pub) . ' endpoint ' . escapeshellarg($target), 20);
			$log[] = $rc === 0 ? 'peer ' . ((string)($p['descr'] ?? '') ?: substr($pub, 0, 8)) . " → {$target}"
			    : 'peer ' . substr($pub, 0, 8) . ': ' . trim($out);
		}
	}
	return $log;
}

/* WireGuard peer reconnect without touching the interface. */
function csfm_wireguard_peer_reconnect($id, $peer) {
	if (!preg_match('/^[0-9a-f]{12}$/', $peer)) {
		throw new Exception('Unknown WireGuard peer');
	}
	foreach (csfm_vpn_list('installedpackages/wireguard/peers/item') as $p) {
		$pub = (string)($p['publickey'] ?? '');
		if (($p['tun'] ?? '') === $id && $pub !== '' && substr(hash('sha256', $pub), 0, 12) === $peer) {
			$endpoint = trim((string)($p['endpoint'] ?? ''));
			if ($endpoint === '') {
				throw new Exception('This peer has no endpoint: it connects to the firewall, not the other way round.');
			}
			$host = strpos($endpoint, ':') !== false && strpos($endpoint, '[') !== 0 ? "[{$endpoint}]" : $endpoint;
			$target = $host . ':' . ((string)($p['port'] ?? '') ?: '51820');
			list($rc, $out) = csfm_exec(escapeshellarg(CSFM_WG) . ' set ' . escapeshellarg($id) . ' peer '
			    . escapeshellarg($pub) . ' endpoint ' . escapeshellarg($target), 20);
			if ($rc !== 0) {
				throw new Exception('wg set failed: ' . trim($out));
			}
			return array('peer ' . ((string)($p['descr'] ?? '') ?: substr($pub, 0, 8)) . " → {$target}");
		}
	}
	throw new Exception('Unknown WireGuard peer');
}

/* ------------------------------------------------------------------ report and task */

/* Every tunnel's monitoring key (kind:id or kind:id:peer) and whether it counts as down. */
function csfm_vpn_down_keys($vpn) {
	$down = array();
	foreach ($vpn['ipsec'] ?? array() as $t) {
		if (in_array($t['status'] ?? '', array('down', 'partial'), true)) {
			$down[] = "ipsec:{$t['id']}";
		}
	}
	foreach ($vpn['openvpn'] ?? array() as $t) {
		if (($t['status'] ?? '') === 'down') {
			$down[] = "openvpn:{$t['id']}";
		}
	}
	foreach ($vpn['wireguard'] ?? array() as $t) {
		if (($t['status'] ?? '') === 'down') {
			$down[] = "wireguard:{$t['id']}";
		}
		foreach ($t['peers'] ?? array() as $p) {
			if (($p['status'] ?? '') === 'down') {
				$down[] = "wireguard:{$t['id']}:{$p['id']}";
			}
		}
	}
	return $down;
}

function csfm_collect_vpn() {
	$vpn = array(
		'ipsec' => csfm_section('ipsec', 'csfm_collect_ipsec'),
		'openvpn' => csfm_section('openvpn', 'csfm_collect_openvpn'),
		'wireguard' => csfm_section('wireguard', 'csfm_collect_wireguard'),
	);
	/* When each tunnel was first seen down, so the server can wait before alerting. */
	$state = csfm_state();
	$prev = is_array($state['vpn_down'] ?? null) ? $state['vpn_down'] : array();
	$now = time();
	$since = array();
	foreach (csfm_vpn_down_keys($vpn) as $key) {
		$since[$key] = (int)($prev[$key] ?? $now);
	}
	if ($since !== $prev) {
		csfm_state_set('vpn_down', $since);
	}
	foreach (array('ipsec', 'openvpn', 'wireguard') as $kind) {
		foreach ($vpn[$kind] as $i => $t) {
			if (isset($since["{$kind}:{$t['id']}"])) {
				$vpn[$kind][$i]['down_since'] = $since["{$kind}:{$t['id']}"];
			}
			foreach ($t['peers'] ?? array() as $j => $p) {
				if (isset($since["{$kind}:{$t['id']}:{$p['id']}"])) {
					$vpn[$kind][$i]['peers'][$j]['down_since'] = $since["{$kind}:{$t['id']}:{$p['id']}"];
				}
			}
		}
	}
	$vpn['collected'] = $now;
	return $vpn;
}

/* payload: {kind: ipsec|openvpn|wireguard, id, action: connect|disconnect|reconnect|kick, peer?, client?} */
function csfm_task_vpn_control($client, $id, $payload) {
	$kind = (string)($payload['kind'] ?? '');
	$target = (string)($payload['id'] ?? '');
	$action = (string)($payload['action'] ?? '');
	$label = (string)($payload['name'] ?? '') ?: $target;
	if (!in_array($action, array('connect', 'disconnect', 'reconnect', 'kick'), true)) {
		throw new Exception("Unknown VPN action '{$action}'");
	}
	if ($kind === 'ipsec') {
		$log = csfm_ipsec_control($target, $action === 'kick' ? '' : $action);
	} elseif ($kind === 'openvpn') {
		$log = csfm_openvpn_control($target, $action, $payload);
	} elseif ($kind === 'wireguard') {
		$log = ($action === 'reconnect' && !empty($payload['peer']))
		    ? csfm_wireguard_peer_reconnect($target, (string)$payload['peer'])
		    : csfm_wireguard_control($target, $action === 'kick' ? '' : $action, $payload);
	} else {
		throw new Exception("Unknown VPN type '{$kind}'");
	}
	csfm_log("VPN {$kind} {$label}: {$action}");
	/* Give the tunnel a moment, then report how it looks now. */
	sleep($action === 'disconnect' || $action === 'kick' ? min(2, CSFM_VPN_SETTLE) : CSFM_VPN_SETTLE);
	$vpn = csfm_collect_vpn();
	$now = '';
	foreach ($vpn[$kind] ?? array() as $t) {
		if ((string)$t['id'] === $target) {
			$now = $t['status'] ?? '';
		}
	}
	$summary = ucfirst($action === 'kick' ? 'disconnect user' : $action) . " {$label}: done."
	    . ($now !== '' ? " It is now {$now}." : '');
	if ($action === 'connect' || $action === 'reconnect') {
		if ($now !== '' && $now !== 'up') {
			$summary .= ' It may take a little longer to come up; the firewall reports again at its next check-in.';
		}
	}
	return array('output' => trim($summary . "\n" . implode("\n", array_filter($log))), 'result' => array('vpn' => $vpn));
}
