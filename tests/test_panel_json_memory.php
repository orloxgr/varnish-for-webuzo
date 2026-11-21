<?php
// Run only on the disposable native Webuzo lab with PHP memory_limit=128M.
// Exercise the real panel entry point and private-response protocol, without
// executing a worker, saving policy settings, or changing the Varnish service.
if (!function_exists('posix_geteuid') || !is_dir('/run/varnish-for-webuzo')) {
    fwrite(STDERR, "Native Linux panel IPC directory required.\n"); exit(77);
}
define('SOFTACULOUS', true);
function register_activation_hook(...$args) {}
function register_deactivation_hook(...$args) {}
function add_filter(...$args) {}
function admin_act(...$args) {}
function enduser_act(...$args) {}
require $argv[1] ?? dirname(__DIR__) . '/varnish-for-webuzo.php';

final class MemoryPanelWorker {
    public $digest;
    public $bytes = 0;
    public $paths = [];
    public function wexec(string $command): array {
        if (!preg_match('/ --request ([0-9a-f]{64})$/D', $command, $match)) throw new RuntimeException('Unexpected worker command.');
        $id = $match[1]; $request = '/run/varnish-for-webuzo/' . $id . '.json';
        $this->paths[] = $request;
        $submitted = json_decode(file_get_contents($request), true);
        if ($submitted['actor'] !== 'root' || $submitted['admin'] !== true || $submitted['action'] !== 'cookie_policies_status') throw new RuntimeException('Native request identity changed.');
        $response = '/run/varnish-for-webuzo/' . $id . '.response';
        $this->paths[] = $response;
        $stream = fopen($response, 'x'); chmod($response, 0600);
        $digest = hash_init('sha256');
        $write = function (string $text) use ($stream, $digest): void {
            fwrite($stream, $text); hash_update($digest, $text); $this->bytes += strlen($text);
        };
        $metadata = [];
        for ($index = 0; $index < 16; $index++) $metadata['explanation_' . $index] = str_repeat('Cookie policy metadata ', 3);
        $row = ['match'=>['kind'=>'exact','value'=>'sample_cookie'], 'description'=>'Accented \u03b1 and HTML </script><p> remain JSON data',
                'profile_actions'=>['basic'=>$metadata,'ultracache'=>$metadata], 'inherited'=>['basic'=>$metadata,'ultracache'=>$metadata]];
        $write('{"ok":true,"cookie_policies":{"rows":[');
        for ($index = 0; $index < 2400; $index++) {
            if ($index) $write(',');
            $write(json_encode(['id'=>'cookie:' . $index] + $row, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT));
        }
        $write('],"settings":{"schemaVersion":2,"rules":[]}},"message":"Complete table"}');
        fclose($stream); $this->digest = hash_final($digest);
        return ['retval'=>0,'output'=>[json_encode(['response'=>$id])]];
    }
}
$W = new MemoryPanelWorker();
register_shutdown_function(static function () use ($W): void {
    foreach ($W->paths as $path) if (is_file($path)) unlink($path);
});
// Keep realistic framework memory resident while the large native response is
// delivered. A streaming output handler checks every byte without retaining it.
$framework = str_repeat('F', 64 * 1024 * 1024);
$SESS = ['user'=>'root','token'=>'fixture-csrf']; $user = []; $globals = [];
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = ['token'=>'fixture-csrf','payload'=>'{"action":"cookie_policies_status","id":null}']; $_FILES = [];
$received = hash_init('sha256'); $bytes = 0;
ob_start(static function (string $text) use ($received, &$bytes): string {
    hash_update($received, $text); $bytes += strlen($text); return '';
}, 8192);
wvw_theme(); ob_end_flush();
if ($bytes !== $W->bytes || hash_final($received) !== $W->digest) throw new RuntimeException('The native response was changed or truncated.');
foreach ($W->paths as $path) if (file_exists($path)) throw new RuntimeException('Private IPC files were not cleaned up.');
echo json_encode(['ok'=>true,'response_bytes'=>$bytes,'peak_bytes'=>memory_get_peak_usage(true),'memory_limit'=>ini_get('memory_limit')]) . "\n";
