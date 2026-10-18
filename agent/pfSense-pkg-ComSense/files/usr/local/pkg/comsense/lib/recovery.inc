<?php
/*
 * ComSense agent - surviving pfSense upgrades.
 *
 * pfSense reinstalls packages from Netgate's repository after an upgrade. This
 * package is not in it, so an upgrade can leave the firewall without its agent.
 * To come back on its own, the agent keeps (outside the package, so pkg never
 * removes them):
 *
 *   /var/db/comsense/recovery/pfSense-pkg-ComSense-<version>.pkg  a copy of itself
 *   /var/db/comsense/recovery/recover.sh                          a boot script
 *
 * and registers the script as a pfSense shellcmd (config.xml, which upgrades
 * keep). At boot the script waits for pfSense's own package reinstall to finish
 * and, if the agent is missing, installs the copy. Its credentials and settings
 * are untouched by an upgrade, so it carries on as the same firewall.
 *
 * Removing the package on purpose (Package Manager) turns this off.
 */

require_once(__DIR__ . '/common.inc');
require_once(__DIR__ . '/client.inc');

if (!defined('CSFM_RECOVERY_DIR')) {
	define('CSFM_RECOVERY_DIR', CSFM_DB_DIR . '/recovery');
}
define('CSFM_RECOVERY_SCRIPT', CSFM_RECOVERY_DIR . '/recover.sh');
define('CSFM_RECOVERY_DISABLED', CSFM_RECOVERY_DIR . '/disabled');
define('CSFM_RECOVERY_SHELLCMD', '/usr/sbin/daemon -f /bin/sh ' . CSFM_RECOVERY_SCRIPT);

function csfm_recovery_script() {
	$dir = CSFM_RECOVERY_DIR;
	$pkg = CSFM_PKG;
	return <<<SH
#!/bin/sh
# ComSense: reinstall the agent if a pfSense upgrade removed it. Written by the
# agent (outside its package, so it outlives it) and run at boot from a pfSense
# shellcmd. Removing the package in Package Manager turns this off.
DIR={$dir}
PKG={$pkg}
[ -f "\${DIR}/disabled" ] && exit 0
\${PKG} info -e pfSense-pkg-ComSense && exit 0
# Let pfSense finish reinstalling its own packages first (up to an hour).
sleep 60
i=0
while [ \$i -lt 120 ] && /bin/pgrep -q -f 'pfSense-upgrade|pkg-static|/usr/sbin/pkg |rc[.]packages'; do
	sleep 30
	i=\$((i + 1))
done
\${PKG} info -e pfSense-pkg-ComSense && exit 0
[ -f "\${DIR}/disabled" ] && exit 0
FILE=\$(/bin/ls -t "\${DIR}"/pfSense-pkg-ComSense-*.pkg 2>/dev/null | /usr/bin/head -1)
[ -n "\${FILE}" ] || exit 0
/usr/bin/logger -t comsense "Agent package missing after boot (pfSense upgrade?); reinstalling \${FILE##*/}"
\${PKG} add -f "\${FILE}" >> "\${DIR}/recover.log" 2>&1

SH;
}

function csfm_recovery_shellcmds() {
	$cmds = csfm_cfg_get('system/shellcmd', array());
	if (!is_array($cmds)) {
		$cmds = ($cmds === null || $cmds === '') ? array() : array($cmds);
	}
	return array_values($cmds);
}

/*
 * Once per cycle, after a successful check-in: keep the package copy, the boot
 * script and the shellcmd in place. Only does work when something is missing.
 */
function csfm_maintain_recovery($client) {
	csfm_ensure_db_dir();
	@mkdir(CSFM_RECOVERY_DIR, 0700, true);
	@unlink(CSFM_RECOVERY_DISABLED);

	$name = 'pfSense-pkg-ComSense-' . CSFM_AGENT_VERSION . '.pkg';
	$copy = CSFM_RECOVERY_DIR . '/' . $name;
	if (!is_file($copy)) {
		try {
			list($data) = $client->download('/agent-package/' . rawurlencode($name), 300);
			if (strlen((string)$data) > 1024) {
				file_put_contents($copy . '.tmp', $data);
				chmod($copy . '.tmp', 0600);
				rename($copy . '.tmp', $copy);
				csfm_log("Kept a copy of {$name} to reinstall the agent after a pfSense upgrade");
			}
		} catch (Exception $e) {
			/* An older server may not have this version; try again next cycle. */
		}
	}
	foreach (glob(CSFM_RECOVERY_DIR . '/pfSense-pkg-ComSense-*.pkg') ?: array() as $old) {
		if ($old !== $copy && is_file($copy)) {
			@unlink($old);
		}
	}

	$script = csfm_recovery_script();
	if (@file_get_contents(CSFM_RECOVERY_SCRIPT) !== $script) {
		file_put_contents(CSFM_RECOVERY_SCRIPT, $script);
		chmod(CSFM_RECOVERY_SCRIPT, 0700);
	}

	$cmds = csfm_recovery_shellcmds();
	if (!in_array(CSFM_RECOVERY_SHELLCMD, $cmds, true)) {
		$cmds[] = CSFM_RECOVERY_SHELLCMD;
		csfm_cfg_set('system/shellcmd', $cmds);
		write_config('ComSense: reinstall the agent at boot if a pfSense upgrade removed it');
	}
}

/* Whether the package is being removed as part of a pfSense upgrade (not on purpose). */
function csfm_removal_is_upgrade() {
	if (!empty(csfm_state()['inflight_upgrade']) || file_exists('/conf/needs_package_sync')) {
		return true;
	}
	exec('/bin/pgrep -q -f pfSense-upgrade', $out, $rc);
	return $rc === 0;
}

/* Package removed on purpose: stop the boot-time reinstall. */
function csfm_disable_recovery() {
	@mkdir(CSFM_RECOVERY_DIR, 0700, true);
	@file_put_contents(CSFM_RECOVERY_DISABLED, gmdate('c') . "\n");
	$cmds = csfm_recovery_shellcmds();
	$kept = array_values(array_filter($cmds, function ($c) { return $c !== CSFM_RECOVERY_SHELLCMD; }));
	if (count($kept) !== count($cmds)) {
		csfm_cfg_set('system/shellcmd', $kept);
		write_config('ComSense: removed; no longer reinstalled at boot');
	}
	foreach (glob(CSFM_RECOVERY_DIR . '/pfSense-pkg-ComSense-*.pkg') ?: array() as $f) {
		@unlink($f);
	}
}
