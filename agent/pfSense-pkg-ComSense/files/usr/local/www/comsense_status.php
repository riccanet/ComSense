<?php
/*
 * comsense_status.php
 *
 * Shows enrollment and connection status of the ComSense agent.
 */

##|+PRIV
##|*IDENT=page-services-comsense
##|*NAME=Services: ComSense Agent
##|*DESCR=Allow access to the ComSense Agent pages.
##|*MATCH=comsense_status.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/comsense.inc');

if ($_POST['checkin_now']) {
	mwexec_bg('/usr/bin/lockf -s -t 0 /var/run/comsense_agent.lock /usr/local/bin/php -f /usr/local/pkg/comsense/agent.php run');
	$savemsg = gettext('A check-in has been started. Refresh this page in a few seconds.');
} elseif ($_POST['unenroll']) {
	csfm_forget_credentials();
	$savemsg = gettext('This firewall has forgotten its credentials. Enter a new enrollment key on the Settings tab to reconnect.');
} elseif ($_POST['guard_confirm']) {
	csfm_guard_confirm('confirmed by an administrator on the firewall');
	$savemsg = gettext('The change was kept; it will not be rolled back.');
} elseif ($_POST['guard_rollback']) {
	$rec = csfm_guard_rollback('rolled back by an administrator on the firewall');
	$savemsg = $rec ? gettext('The previous configuration was restored.') : gettext('There was no change to roll back.');
} elseif ($_POST['restart']) {
	comsense_resync();
	$savemsg = gettext('Agent restarted.');
}

$settings = csfm_settings();
$creds = csfm_credentials();
$state = csfm_state();

$pgtitle = array(gettext('Services'), gettext('ComSense Agent'), gettext('Status'));
$pglinks = array('', '/pkg_edit.php?xml=comsense.xml', '@self');
include('head.inc');

if ($savemsg) {
	print_info_box($savemsg, 'success');
}
if (!empty($state['last_error'])) {
	print_info_box(htmlspecialchars($state['last_error']['message']) . ' (' . htmlspecialchars($state['last_error']['at']) . ')', 'danger');
}

$guard = csfm_guard();
if ($guard !== null) {
	$labels = implode('; ', array_map(function ($t) { return $t['label']; }, $guard['tasks']));
	print_info_box(sprintf(gettext('A change from the management server is on probation until %s: %s. If the firewall '
	    . 'cannot reach the server by then, the previous configuration is restored automatically.'),
	    htmlspecialchars(date('Y-m-d H:i:s', (int)$guard['deadline'])), htmlspecialchars($labels)), 'warning');
}
if (!empty($state['last_rollback'])) {
	$rb = $state['last_rollback'];
	print_info_box(sprintf(gettext('Last automatic rollback: %s, on %s (%s).'), htmlspecialchars($rb['changes']),
	    htmlspecialchars($rb['rolled_back_at']), htmlspecialchars($rb['reason'])), 'info');
}

$tab_array = array(
	array(gettext('Settings'), false, '/pkg_edit.php?xml=comsense.xml'),
	array(gettext('Status'), true, '/comsense_status.php'),
);
display_top_tabs($tab_array);

function csfm_row($label, $value) {
	echo '<tr><th>' . htmlspecialchars($label) . '</th><td>' . $value . '</td></tr>';
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Connection')?></h2></div>
	<div class="panel-body">
		<table class="table table-striped table-condensed">
			<tbody>
<?php
csfm_row(gettext('Agent'), empty($settings['enable']) ? gettext('Disabled') : (comsense_running() ? gettext('Running') : gettext('Stopped')));
csfm_row(gettext('Agent version'), htmlspecialchars(CSFM_AGENT_VERSION));
csfm_row(gettext('Server'), htmlspecialchars($settings['server_url'] ?? ''));
csfm_row(gettext('Enrolled'), csfm_is_enrolled()
    ? sprintf(gettext('Yes, since %s'), htmlspecialchars($creds['enrolled_at'] ?? ''))
    : gettext('No'));
csfm_row(gettext('Device ID'), htmlspecialchars($creds['device_id'] ?? ''));
csfm_row(gettext('Server status'), htmlspecialchars($state['device_status'] ?? ''));
csfm_row(gettext('Last check-in'), htmlspecialchars($state['last_checkin'] ?? gettext('never')));
csfm_row(gettext('Last backup'), htmlspecialchars($state['last_backup']['at'] ?? gettext('never')));
csfm_row(gettext('Allowed actions'), htmlspecialchars(implode(', ', csfm_capabilities()) ?: gettext('monitoring only')));
?>
			</tbody>
		</table>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Policies managed on this firewall')?></h2></div>
	<div class="panel-body">
		<table class="table table-striped table-condensed">
			<thead><tr><th><?=gettext('Policy')?></th><th><?=gettext('Type')?></th><th><?=gettext('Revision')?></th></tr></thead>
			<tbody>
<?php foreach ($state['policies'] as $pid => $p): ?>
				<tr>
					<td><?=htmlspecialchars(($p['name'] ?? '') . " (#{$pid})")?></td>
					<td><?=htmlspecialchars($p['type'] ?? '')?></td>
					<td><?=htmlspecialchars((string)($p['revision'] ?? ''))?></td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>

<form method="post">
	<button type="submit" name="checkin_now" value="1" class="btn btn-primary"><i class="fa-solid fa-rotate"></i> <?=gettext('Check in now')?></button>
<?php if ($guard !== null): ?>
	<button type="submit" name="guard_confirm" value="1" class="btn btn-success"><i class="fa-solid fa-check"></i> <?=gettext('Keep the change')?></button>
	<button type="submit" name="guard_rollback" value="1" class="btn btn-warning"
		onclick="return confirm('<?=gettext('Restore the configuration from before the change now?')?>');">
		<i class="fa-solid fa-rotate-left"></i> <?=gettext('Roll back now')?></button>
<?php endif; ?>
	<button type="submit" name="restart" value="1" class="btn btn-default"><i class="fa-solid fa-play-circle"></i> <?=gettext('Restart agent')?></button>
	<button type="submit" name="unenroll" value="1" class="btn btn-danger"
		onclick="return confirm('<?=gettext('Forget this firewall\'s credentials? You will need a new enrollment key to reconnect.')?>');">
		<i class="fa-solid fa-unlink"></i> <?=gettext('Unenroll')?></button>
</form>
<?php include('foot.inc'); ?>
