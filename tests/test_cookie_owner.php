<?php
define('SOFTACULOUS', true);
function register_activation_hook(...$args) {}
function register_deactivation_hook(...$args) {}
function add_filter(...$args) {}
function admin_act(...$args) {}
function enduser_act(...$args) {}
require dirname(__DIR__) . '/varnish-for-webuzo.php';
function denied(callable $call): void {
    try { $call(); } catch (Throwable $error) { return; }
    throw new RuntimeException('An unauthorized cookie policy request was accepted.');
}
$SESS = ['user'=>'example','token'=>'valid'];
$_POST = ['token'=>'valid','payload'=>'{"action":"cookie_policies_status"}'];
$request = wvw_api_request('valid', false);
if ($request['actor'] !== 'example' || $request['admin'] !== false) throw new RuntimeException('Native owner identity was not used.');
$_POST['payload'] = '{"action":"cookie_policies_save","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","settings":{}}';
if (wvw_api_request('valid', false)['actor'] !== 'example') throw new RuntimeException('Owner save identity changed.');
$_POST['payload'] = '{"action":"cookie_integration_status","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","integration":{"enabled":true,"url":"https://example.test/wp-json/ultracache/v1/cookie-policy-control"}}';
if (wvw_api_request('valid', false)['admin'] !== false) throw new RuntimeException('Connection check escalated to administrator.');
foreach (['status','install','configure','cookie_delivery','profile_rules'] as $operation) {
    $_POST['payload'] = json_encode(['action'=>$operation]);
    denied(static fn() => wvw_api_request('valid', false));
}
foreach (['actor'=>'root','admin'=>true] as $field => $value) {
    $_POST['payload'] = json_encode(['action'=>'cookie_policies_status',$field=>$value]);
    denied(static fn() => wvw_api_request('valid', false));
}
foreach (['actor','admin'] as $field) {
    $_POST['payload'] = json_encode(['action'=>'cookie_policies_status',$field=>null]);
    denied(static fn() => wvw_api_request('valid', false));
}
$_POST['payload'] = '{"action":"cookie_policies_status"}';
$_POST['token'] = 'wrong'; denied(static fn() => wvw_api_request('valid', false));
$_POST['token'] = 'valid'; denied(static fn() => wvw_api_request('valid', true));
$SESS = ['user'=>'root','is_reseller'=>true];
$_POST['payload'] = '{"action":"install"}'; denied(static fn() => wvw_api_request('valid', false));
$SESS = ['user'=>'root'];
$request = wvw_api_request('valid', false);
if ($request['actor'] !== 'root' || $request['admin'] !== true) throw new RuntimeException('Native administrator identity lost.');
$rows = [];
for ($index=0;$index<1500;$index++) $rows[] = ['id'=>'custom:'.$index,'match'=>['kind'=>'exact','value'=>'cookie_'.$index],'description'=>str_repeat('Description ',80),'action'=>'shared'];
$_POST['payload'] = json_encode(['action'=>'cookie_policies_save','id'=>str_repeat('a',32),'settings'=>['schemaVersion'=>1,'rules'=>$rows]]);
if (strlen($_POST['payload']) <= 1024*1024 || count(wvw_api_request('valid', false)['settings']['rules']) !== 1500) throw new RuntimeException('A valid large spreadsheet was rejected.');
echo "Cookie policy native session, action scope, CSRF and demo checks passed.\n";
