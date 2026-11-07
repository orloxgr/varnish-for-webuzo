<?php
/**
 * Plugin Name: Varnish Cache for Webuzo
 * Description: Clear this site's Varnish cache from WordPress.
 * Version: 0.1.0
 * Author: Byron Iniotakis
 * Author URI: https://www.iniotakis.com
 * License: GPL-3.0-or-later
 * Text Domain: varnish-cache-for-webuzo
 * Requires PHP: 7.4
 * Requires at least: 6.0
 */
namespace VarnishForWebuzo;
if (!defined('ABSPATH')) { exit; }

function credential(): array {
    if (!function_exists('curl_init') || !defined('CURLOPT_UNIX_SOCKET_PATH')) {
        throw new \RuntimeException(__('The hosting provider needs to enable PHP cURL with Unix socket support.', 'varnish-cache-for-webuzo'));
    }
    if (!function_exists('posix_getpwuid') || !function_exists('posix_geteuid')) {
        throw new \RuntimeException(__('The hosting provider needs to enable PHP POSIX support.', 'varnish-cache-for-webuzo'));
    }
    $account = posix_getpwuid(posix_geteuid());
    $host = strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST));
    if (!is_array($account) || empty($account['dir']) || !preg_match('/^[a-z0-9.-]+$/D', $host)) {
        throw new \RuntimeException(__('Could not identify this hosting account.', 'varnish-cache-for-webuzo'));
    }
    require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
    require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
    $filesystem = new \WP_Filesystem_Direct(null);
    $directory = rtrim($account['dir'], '/') . '/.varnish-for-webuzo/';
    foreach ($filesystem->dirlist($directory, false, false) ?: [] as $name => $info) {
        if (!preg_match('/^[0-9a-f]{32}\.json$/D', $name) || $info['type'] !== 'f') { continue; }
        $raw = $filesystem->get_contents($directory . $name);
        if (!is_string($raw) || strlen($raw) > 65536) { continue; }
        $data = json_decode($raw, true);
        if (is_array($data) && is_array($data['names'] ?? null) && in_array($host, $data['names'], true) &&
            is_string($data['token'] ?? null) && preg_match('/^[0-9a-f]{64}$/D', $data['token'])) {
            return ['host'=>$host, 'token'=>$data['token']];
        }
    }
    throw new \RuntimeException(__('Ask your hosting provider to enable Varnish for this site.', 'varnish-cache-for-webuzo'));
}
function purge_site(array $data): void {
    $bound = false;
    $identity = wp_generate_uuid4();
    $endpoint = 'http://localhost/';
    $configure = static function($handle, array $arguments, string $url) use ($data, $identity, $endpoint, &$bound): void {
        if ($url !== $endpoint || ($arguments['method'] ?? '') !== 'PURGE' ||
            ($arguments['headers']['X-Webuzo-Varnish-Request'] ?? '') !== $identity) { return; }
        // The token is attached only after binding this request to the protected
        // Unix socket. Other HTTP transports never receive the credential.
        if (!curl_setopt($handle, CURLOPT_UNIX_SOCKET_PATH, '/run/varnish-for-webuzo-cache/frontend.sock') ||
            !curl_setopt($handle, CURLOPT_PROXY, '') ||
            !curl_setopt($handle, CURLOPT_HTTPHEADER, ['Host: ' . $data['host'], 'X-Webuzo-Varnish-Token: ' . $data['token']])) {
            throw new \RuntimeException(__('Could not connect to the local cache service.', 'varnish-cache-for-webuzo'));
        }
        $bound = true;
    };
    add_action('http_api_curl', $configure, PHP_INT_MAX, 3);
    try {
        $response = wp_remote_request($endpoint, ['method'=>'PURGE', 'timeout'=>10, 'redirection'=>0,
            'headers'=>['X-Webuzo-Varnish-Request'=>$identity]]);
    } finally { remove_action('http_api_curl', $configure, PHP_INT_MAX); }
    if (!$bound || is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
        throw new \RuntimeException(__('Could not clear the cache. Contact your hosting provider.', 'varnish-cache-for-webuzo'));
    }
}
function button(): void {
    echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
    echo '<input type="hidden" name="action" value="varnish_for_webuzo_purge">';
    wp_nonce_field('varnish_for_webuzo_purge');
    submit_button(__('Clear this site’s cache', 'varnish-cache-for-webuzo'), 'primary', 'submit', false);
    echo '</form>';
}
function page(): void {
    if (!current_user_can('manage_options')) { wp_die(esc_html__('Administrator access is required.', 'varnish-cache-for-webuzo')); }
    echo '<div class="wrap"><h1>' . esc_html__('Varnish Cache', 'varnish-cache-for-webuzo') . '</h1>';
    echo '<p>' . esc_html__('Clear cached pages so visitors can see your latest changes.', 'varnish-cache-for-webuzo') . '</p>';
    if (isset($_GET['varnish-cleared']) && $_GET['varnish-cleared'] === '1') {
        echo '<div class="notice notice-success"><p>' . esc_html__('This site’s cache has been cleared.', 'varnish-cache-for-webuzo') . '</p></div>';
    }
    try { credential(); button(); }
    catch (\RuntimeException $error) { echo '<p>' . esc_html($error->getMessage()) . '</p>'; }
    echo '</div>';
}
add_action('admin_menu', static function(): void {
    add_management_page(__('Varnish Cache', 'varnish-cache-for-webuzo'), __('Varnish Cache', 'varnish-cache-for-webuzo'), 'manage_options', 'varnish-for-webuzo', __NAMESPACE__ . '\\page');
});
add_action('admin_post_varnish_for_webuzo_purge', static function(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !current_user_can('manage_options')) {
        wp_die(esc_html__('Administrator access is required.', 'varnish-cache-for-webuzo'), '', ['response'=>403]);
    }
    check_admin_referer('varnish_for_webuzo_purge');
    try {
        $data = credential();
        purge_site($data);
        wp_safe_redirect(add_query_arg(['page'=>'varnish-for-webuzo', 'varnish-cleared'=>'1'], admin_url('tools.php')));
        exit;
    } catch (\RuntimeException $error) { wp_die(esc_html($error->getMessage())); }
});
