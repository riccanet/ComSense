<?php
/*
 * pfmanager.priv.inc
 */

global $priv_list;

$priv_list['page-services-pfmanager'] = array();
$priv_list['page-services-pfmanager']['name'] = 'WebCfg - Services: PfManager Agent';
$priv_list['page-services-pfmanager']['descr'] = 'Allow access to the PfManager Agent package GUI';
$priv_list['page-services-pfmanager']['match'] = array();
$priv_list['page-services-pfmanager']['match'][] = 'pkg_edit.php?xml=pfmanager.xml*';
$priv_list['page-services-pfmanager']['match'][] = 'pfmanager_status.php*';
