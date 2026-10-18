<?php
/*
 * comsense.priv.inc
 */

global $priv_list;

$priv_list['page-services-comsense'] = array();
$priv_list['page-services-comsense']['name'] = 'WebCfg - Services: ComSense Agent';
$priv_list['page-services-comsense']['descr'] = 'Allow access to the ComSense Agent package GUI';
$priv_list['page-services-comsense']['match'] = array();
$priv_list['page-services-comsense']['match'][] = 'pkg_edit.php?xml=comsense.xml*';
$priv_list['page-services-comsense']['match'][] = 'comsense_status.php*';
