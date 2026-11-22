<?php
/*
Plugin Name: Varnish for Webuzo
Version: 0.12.9
Description: Serve static files with Nginx and cache public HTTP responses with Varnish.
Author: Byron Iniotakis
Author URI: https://www.iniotakis.com
License: GPL-3.0-or-later
*/
if (!defined('SOFTACULOUS')) { http_response_code(403); exit; }
register_activation_hook(__FILE__, 'wvw_activate');
register_deactivation_hook(__FILE__, 'wvw_deactivate');
add_filter('admin_menu', 'wvw_menu', 10, 1);
admin_act('varnish-for-webuzo', 'wvw_page');
enduser_act('varnish-for-webuzo', 'wvw_page');
add_filter('enduser_cats_icons', 'wvw_user_menu', 10, 1);

function wvw_user_menu($menu) {
    $menu['security']['icons']['varnish-for-webuzo'] = ['name'=>'Cookie cache policies','href'=>'index.php?act=varnish-for-webuzo','icon'=>'fas fa-cookie-bite'];
    return $menu;
}

function wvw_lifecycle(string $action): bool {
    global $W, $error;
    if (!in_array($action, ['install','remove'], true)) return false;
    $result = $W->wexec('/usr/bin/python3 -I -B ' . escapeshellarg(__DIR__ . '/src/lifecycle.py') . ' ' . $action);
    $data = json_decode(implode("\n", $result['output'] ?? []), true);
    if (($result['retval'] ?? 1) !== 0 || empty($data['ok'])) {
        $error[] = is_array($data) ? ($data['error'] ?? 'Plugin setup failed.') : 'Invalid setup response.';
        return false;
    }
    return true;
}
function wvw_activate() { return wvw_lifecycle('install'); }
function wvw_deactivate() { return wvw_lifecycle('remove'); }
function wvw_menu($menu) {
    $menu['varnish-for-webuzo'] = ['name'=>'Varnish Cache','href'=>'index.php?act=varnish-for-webuzo','icon'=>'fas fa-bolt'];
    return $menu;
}
function wvw_page() {
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') { wvw_theme(); exit; }
    theme_for_act('wvw_theme', 'varnish-for-webuzo');
}
function wvw_bridge(array $request): string {
    global $W;
    $identity = bin2hex(random_bytes(32));
    $path = '/run/varnish-for-webuzo/' . $identity . '.json';
    $payload = json_encode($request, JSON_THROW_ON_ERROR);
    $mask = umask(0077);
    try { $handle = fopen($path, 'x'); } finally { umask($mask); }
    if ($handle === false) throw new RuntimeException('Activate Varnish for Webuzo first.');
    try {
        $offset = 0;
        while ($offset < strlen($payload)) {
            $written = fwrite($handle, substr($payload, $offset));
            if ($written === false || $written === 0) throw new RuntimeException('Could not send the request.');
            $offset += $written;
        }
        fclose($handle); $handle = null;
        $result = $W->wexec('/usr/bin/python3 -I -B ' . escapeshellarg(__DIR__ . '/src/addon.py') . ' --request ' . $identity);
        $json = implode("\n", $result['output'] ?? []);
        $data = json_decode($json, true);
        if (!is_array($data)) throw new RuntimeException('Invalid worker response.');
        if (($data['response'] ?? '') === $identity) {
            $response = '/run/varnish-for-webuzo/' . $identity . '.response';
            $info = lstat($response);
            if ($info === false || ($info['mode'] & 0170000) !== 0100000 || ($info['mode'] & 0777) !== 0600 || $info['nlink'] !== 1 || $info['uid'] !== posix_geteuid()) throw new RuntimeException('Invalid private response file.');
            // The root worker has already serialized this authenticated response.
            // Expanding the complete cookie table into PHP arrays and encoding it
            // again exhausts the native panel's memory before it can send JSON.
            $json = file_get_contents($response);
            if ($json === false) throw new RuntimeException('Could not read the private worker response.');
        }
        return $json;
    } finally {
        if (is_resource($handle)) fclose($handle);
        if (is_file($path)) unlink($path);
        $response = '/run/varnish-for-webuzo/' . $identity . '.response';
        if (is_file($response)) unlink($response);
    }
}
function wvw_api(string $csrf, bool $demo): string {
    return wvw_bridge(wvw_api_request($csrf, $demo));
}
function wvw_api_request(string $csrf, bool $demo): array {
    global $SESS;
    if ($demo) throw new RuntimeException('Changes are unavailable in demo mode.');
    if (!is_string($_POST['token'] ?? null) || !hash_equals($csrf, $_POST['token'])) throw new RuntimeException('Session expired. Reload this page.');
    $payload = $_POST['payload'] ?? '';
    if (!is_string($payload) || !empty($_FILES)) throw new RuntimeException('Invalid request.');
    $request = json_decode($payload, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($request) || array_key_exists('actor',$request) || array_key_exists('admin',$request)) throw new RuntimeException('Invalid request.');
    $actor = $SESS['user'] ?? '';
    if (!is_string($actor) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $actor)) throw new RuntimeException('Session expired.');
    $administrator = $actor === 'root' && empty($SESS['is_reseller']);
    if (!$administrator && !in_array($request['action'] ?? '', ['cookie_policies_status','cookie_policies_save','cookie_integration_status'], true)) {
        throw new RuntimeException('Webuzo administrator access is required.');
    }
    $request['actor'] = $actor; $request['admin'] = $administrator;
    return $request;
}
function wvw_theme() {
    global $SESS, $user, $globals;
    $csrf = $SESS['token'] ?? '';
    $ajax = ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST';
    $actor = $SESS['user'] ?? '';
    $isAdmin = $actor === 'root' && empty($SESS['is_reseller']);
    if (!is_string($actor) || !preg_match('/^[A-Za-z0-9][A-Za-z0-9_-]*$/D', $actor) || ($actor === 'root' && !$isAdmin) || !is_string($csrf) || $csrf === '') {
        http_response_code(403);
        if ($ajax) { header('Content-Type: application/json'); echo json_encode(['ok'=>false,'error'=>'Webuzo administrator access is required.']); }
        return;
    }
    if ($ajax) {
        header('Content-Type: application/json; charset=UTF-8'); header('Cache-Control: no-store'); header('X-Content-Type-Options: nosniff');
        if (!$isAdmin) {
            $submitted = is_string($_POST['payload'] ?? null) ? json_decode($_POST['payload'], true) : null;
            if (!is_array($submitted) || !in_array($submitted['action'] ?? '', ['cookie_policies_status','cookie_policies_save','cookie_integration_status'], true)) {
                http_response_code(403); echo json_encode(['ok'=>false,'error'=>'Webuzo administrator access is required.']); return;
            }
        }
        try { $result = wvw_api($csrf, !empty($user['demo']) || !empty($globals['demo'])); }
        catch (Throwable $exception) { $result = json_encode(['ok'=>false,'error'=>$exception->getMessage()], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE); }
        echo $result;
        return;
    }
    $escape = static fn($value) => htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    require __DIR__ . ($isAdmin ? '/panel/index.php' : '/panel/cookie-owner.php');
}
