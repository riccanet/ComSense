<?php
/*
 * pfmanager_status.php
 *
 * Shows enrollment and connection status of the PfManager agent.
 */

##|+PRIV
##|*IDENT=page-services-pfmanager
##|*NAME=Services: PfManager Agent
##|*DESCR=Allow access to the PfManager Agent pages.
##|*MATCH=pfmanager_status.php*
##|-PRIV

require_once('guiconfig.inc');
require_once('/usr/local/pkg/pfmanager.inc');

if ($_POST['checkin_now']) {
	mwexec_bg('/usr/bin/lockf -s -t 0 /var/run/pfmanager_agent.lock /usr/local/bin/php -f /usr/local/pkg/pfmanager/agent.php run');
	$savemsg = gettext('A check-in has been started. Refresh this page in a few seconds.');
} elseif ($_POST['unenroll']) {
	pfm_forget_credentials();
	$savemsg = gettext('This firewall has forgotten its credentials. Enter a new enrollment key on the Settings tab to reconnect.');
} elseif ($_POST['restart']) {
	pfmanager_resync();
	$savemsg = gettext('Agent restarted.');
}

$settings = pfm_settings();
$creds = pfm_credentials();
$state = pfm_state();

$pgtitle = array(gettext('Services'), gettext('PfManager Agent'), gettext('Status'));
$pglinks = array('', '/pkg_edit.php?xml=pfmanager.xml', '@self');
include('head.inc');

if ($savemsg) {
	print_info_box($savemsg, 'success');
}
if (!empty($state['last_error'])) {
	print_info_box(htmlspecialchars($state['last_error']['message']) . ' (' . htmlspecialchars($state['last_error']['at']) . ')', 'danger');
}

$tab_array = array(
	array(gettext('Settings'), false, '/pkg_edit.php?xml=pfmanager.xml'),
	array(gettext('Status'), true, '/pfmanager_status.php'),
);
display_top_tabs($tab_array);

function pfm_row($label, $value) {
	echo '<tr><th>' . htmlspecialchars($label) . '</th><td>' . $value . '</td></tr>';
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Connection')?></h2></div>
	<div class="panel-body">
		<table class="table table-striped table-condensed">
			<tbody>
<?php
pfm_row(gettext('Agent'), empty($settings['enable']) ? gettext('Disabled') : (pfmanager_running() ? gettext('Running') : gettext('Stopped')));
pfm_row(gettext('Agent version'), htmlspecialchars(PFM_AGENT_VERSION));
pfm_row(gettext('Server'), htmlspecialchars($settings['server_url'] ?? ''));
pfm_row(gettext('Enrolled'), pfm_is_enrolled()
    ? sprintf(gettext('Yes, since %s'), htmlspecialchars($creds['enrolled_at'] ?? ''))
    : gettext('No'));
pfm_row(gettext('Device ID'), htmlspecialchars($creds['device_id'] ?? ''));
pfm_row(gettext('Server status'), htmlspecialchars($state['device_status'] ?? ''));
pfm_row(gettext('Last check-in'), htmlspecialchars($state['last_checkin'] ?? gettext('never')));
pfm_row(gettext('Last backup'), htmlspecialchars($state['last_backup']['at'] ?? gettext('never')));
pfm_row(gettext('Allowed actions'), htmlspecialchars(implode(', ', pfm_capabilities()) ?: gettext('monitoring only')));
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
	<button type="submit" name="restart" value="1" class="btn btn-default"><i class="fa-solid fa-play-circle"></i> <?=gettext('Restart agent')?></button>
	<button type="submit" name="unenroll" value="1" class="btn btn-danger"
		onclick="return confirm('<?=gettext('Forget this firewall\'s credentials? You will need a new enrollment key to reconnect.')?>');">
		<i class="fa-solid fa-unlink"></i> <?=gettext('Unenroll')?></button>
</form>
<?php include('foot.inc'); ?>
