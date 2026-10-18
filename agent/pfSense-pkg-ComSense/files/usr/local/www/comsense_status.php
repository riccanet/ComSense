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

$savemsg = '';
if (!empty($_POST['checkin_now'])) {
	mwexec_bg('/usr/bin/lockf -s -t 0 /var/run/comsense_agent.lock /usr/local/bin/php -f /usr/local/pkg/comsense/agent.php run');
	$savemsg = gettext('A check-in has been started. Refresh this page in a few seconds.');
} elseif (!empty($_POST['unenroll'])) {
	csfm_forget_credentials();
	$savemsg = gettext('This firewall has forgotten its credentials. Enter a new enrollment key on the Settings tab to reconnect.');
} elseif (!empty($_POST['guard_confirm'])) {
	csfm_guard_confirm('confirmed by an administrator on the firewall');
	$savemsg = gettext('The change was kept; it will not be rolled back.');
} elseif (!empty($_POST['guard_rollback'])) {
	$rec = csfm_guard_rollback('rolled back by an administrator on the firewall');
	$savemsg = $rec ? gettext('The previous configuration was restored.') : gettext('There was no change to roll back.');
} elseif (!empty($_POST['restart'])) {
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

/* "2026-10-18 14:25 (3 min ago)" from an ISO time or unix timestamp. */
function csfm_when($value, $never = null) {
	$ts = is_numeric($value) ? (int)$value : (is_string($value) && $value !== '' ? strtotime($value) : false);
	if (!$ts) {
		return htmlspecialchars($never ?? gettext('never'));
	}
	$ago = time() - $ts;
	if ($ago < 0) {
		$rel = sprintf(gettext('in %d min'), ceil(-$ago / 60));
	} elseif ($ago < 90) {
		$rel = gettext('just now');
	} elseif ($ago < 5400) {
		$rel = sprintf(gettext('%d min ago'), round($ago / 60));
	} elseif ($ago < 172800) {
		$rel = sprintf(gettext('%d h ago'), round($ago / 3600));
	} else {
		$rel = sprintf(gettext('%d days ago'), round($ago / 86400));
	}
	return htmlspecialchars(date('Y-m-d H:i', $ts)) . ' <span class="text-muted">(' . htmlspecialchars($rel) . ')</span>';
}

if (!empty($state['last_error'])) {
	print_info_box(htmlspecialchars($state['last_error']['message']) . ' &middot; ' . csfm_when($state['last_error']['at']), 'danger');
}
$guard = csfm_guard();
if ($guard !== null) {
	$labels = implode('; ', array_map(function ($t) { return $t['label']; }, $guard['tasks']));
	print_info_box(sprintf(gettext('Change on probation until %s: %s. It is rolled back automatically if the server cannot be reached by then.'),
	    csfm_when($guard['deadline']), htmlspecialchars($labels)), 'warning');
}
$rb = $state['last_rollback'] ?? null;
if (is_array($rb) && time() - (int)strtotime($rb['rolled_back_at'] ?? '') < 7 * 86400) {
	print_info_box(sprintf(gettext('Rolled back %s: %s (%s).'), csfm_when($rb['rolled_back_at']),
	    htmlspecialchars($rb['changes']), htmlspecialchars($rb['reason'])), 'info');
}

$tab_array = array(
	array(gettext('Settings'), false, '/pkg_edit.php?xml=comsense.xml'),
	array(gettext('Status'), true, '/comsense_status.php'),
);
display_top_tabs($tab_array);

$enabled = !empty($settings['enable']);
$running = $enabled && comsense_running();
$agent = !$enabled ? '<span class="text-muted">' . gettext('Disabled') . '</span>'
    : ($running ? '<span class="text-success"><i class="fa-solid fa-circle-check"></i> ' . gettext('Running') . '</span>'
    : '<span class="text-danger"><i class="fa-solid fa-circle-xmark"></i> ' . gettext('Stopped') . '</span>');
$device_id = $creds['device_id'] ?? '';
$enrolled = csfm_is_enrolled()
    ? csfm_when($creds['enrolled_at'] ?? '') . ($device_id !== '' ? ' &middot; <span class="text-muted" title="' . htmlspecialchars($device_id) . '">'
        . htmlspecialchars(substr($device_id, 0, 8)) . '&hellip;</span>' : '')
    : gettext('Not enrolled');
$caps = csfm_capabilities();

function csfm_rows($rows) {
	echo '<table class="table table-condensed" style="margin-bottom:0"><tbody>';
	foreach ($rows as $label => $value) {
		echo '<tr><th style="width:38%">' . htmlspecialchars($label) . '</th><td>' . $value . '</td></tr>';
	}
	echo '</tbody></table>';
}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('ComSense Agent')?></h2></div>
	<div class="panel-body">
		<div class="row">
			<div class="col-sm-6"><?php csfm_rows(array(
				gettext('Agent') => $agent . ' <span class="text-muted">v' . htmlspecialchars(CSFM_AGENT_VERSION) . '</span>',
				gettext('Server') => htmlspecialchars($settings['server_url'] ?? '') . (!empty($state['device_status'])
				    ? ' <span class="label label-default">' . htmlspecialchars($state['device_status']) . '</span>' : ''),
				gettext('Enrolled') => $enrolled,
			)); ?></div>
			<div class="col-sm-6"><?php csfm_rows(array(
				gettext('Last check-in') => csfm_when($state['last_checkin'] ?? ''),
				gettext('Last backup') => csfm_when($state['last_backup']['at'] ?? ''),
				gettext('Allowed actions') => $caps ? htmlspecialchars(implode(', ', $caps)) : gettext('monitoring only'),
			)); ?></div>
		</div>
<?php if (!empty($state['policies'])): ?>
		<p style="margin:10px 0 0"><strong><?=gettext('Managed policies:')?></strong>
<?php
		$items = array();
		foreach ($state['policies'] as $pid => $p) {
			$items[] = htmlspecialchars(($p['name'] ?? "#{$pid}") . ' (' . ($p['type'] ?? '') . (isset($p['revision']) ? ", r{$p['revision']}" : '') . ')');
		}
		echo implode(' &middot; ', $items);
?></p>
<?php endif; ?>
	</div>
	<div class="panel-footer">
		<form method="post" style="margin:0">
			<button type="submit" name="checkin_now" value="1" class="btn btn-sm btn-primary"><i class="fa-solid fa-rotate"></i> <?=gettext('Check in now')?></button>
<?php if ($guard !== null): ?>
			<button type="submit" name="guard_confirm" value="1" class="btn btn-sm btn-success"><i class="fa-solid fa-check"></i> <?=gettext('Keep the change')?></button>
			<button type="submit" name="guard_rollback" value="1" class="btn btn-sm btn-warning"
				onclick="return confirm(<?=htmlspecialchars(json_encode(gettext('Restore the configuration from before the change now?')))?>);">
				<i class="fa-solid fa-rotate-left"></i> <?=gettext('Roll back now')?></button>
<?php endif; ?>
			<button type="submit" name="restart" value="1" class="btn btn-sm btn-default"><i class="fa-solid fa-play-circle"></i> <?=gettext('Restart agent')?></button>
			<button type="submit" name="unenroll" value="1" class="btn btn-sm btn-danger pull-right"
				onclick="return confirm(<?=htmlspecialchars(json_encode(gettext("Forget this firewall's credentials? You will need a new enrollment key to reconnect.")))?>);">
				<i class="fa-solid fa-unlink"></i> <?=gettext('Unenroll')?></button>
		</form>
	</div>
</div>
<?php include('foot.inc'); ?>
