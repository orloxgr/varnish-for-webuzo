<?php
define('SOFTACULOUS', true);
function register_activation_hook(...$args) {}
function register_deactivation_hook(...$args) {}
function add_filter(...$args) {}
function admin_act(...$args) {}
require dirname(__DIR__) . '/varnish-for-webuzo.php';
function rejects(callable $callback, string $message): void {
    try { $callback(); } catch (Throwable $error) {
        if (strpos($error->getMessage(), $message) !== false) return;
        throw $error;
    }
    throw new RuntimeException('Expected request rejection: ' . $message);
}
$_POST = ['payload'=>'{"action":"status"}'];
rejects(static fn() => wvw_api('valid', false), 'Session expired');
$_POST['token'] = ['valid']; rejects(static fn() => wvw_api('valid', false), 'Session expired');
$_POST['token'] = 'wrong'; rejects(static fn() => wvw_api('valid', false), 'Session expired');
$_POST['token'] = 'valid'; rejects(static fn() => wvw_api('valid', true), 'demo mode');
$_POST['payload'] = '{"action":"status","actor":"root"}'; rejects(static fn() => wvw_api('valid', false), 'Invalid request');
$_POST['payload'] = '{"action":"status","admin":true}'; rejects(static fn() => wvw_api('valid', false), 'Invalid request');
$_POST['payload'] = '{}'; $_FILES = ['unexpected'=>[]]; rejects(static fn() => wvw_api('valid', false), 'Invalid request'); $_FILES = [];
$_SERVER['REQUEST_METHOD'] = 'POST'; $SESS = ['user'=>'customer','token'=>'valid'];
ob_start(); wvw_theme(); $result = json_decode(ob_get_clean(), true);
if (http_response_code() !== 403 || $result['ok'] !== false) throw new RuntimeException('Customer reached administrator actions.');
echo "Eight native panel rejection checks passed.\n";
