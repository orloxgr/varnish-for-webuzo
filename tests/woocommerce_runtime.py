"""Actual WooCommerce session isolation on two disposable Webuzo accounts.

Requires WooCommerce and Storefront already active on the first site. Creates
two guest sessions, one temporary product and an authenticated test-only AJAX
callback. All temporary fixtures and the original site profile are restored.
"""
import argparse
import copy
import hashlib
import http.client
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import urllib.parse
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--disposable', action='store_true', required=True)
parser.add_argument('--address', required=True)
parser.add_argument('--sites', nargs=2, required=True)
parser.add_argument('--php', required=True)
parser.add_argument('--wp', required=True)
args = parser.parse_args()
if os.geteuid() != 0:
    parser.error('Run as root only on a disposable Linux server')
ipaddress.ip_address(args.address)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import engine

config = engine.settings()
sites = [next(s for s in config['sites'].values() if s['domain'] == name) for name in args.sites]
if len({s['uid'] for s in sites}) != 2 or any(not s['enabled'] or s['error'] for s in sites):
    parser.error('Select two enabled sites on separate accounts')
site, other = sites
original = copy.deepcopy(site)
identity = secrets.token_hex(12)
key = secrets.token_hex(32)
marker = 'WVW-PRIVATE-NOTICE-' + identity
hook = 'wvw_session_test_' + identity
fixtures = []
product = None
checks = []


def wp(code):
    result = subprocess.run(
        [args.php, '-d', 'memory_limit=512M', args.wp, '--path=' + site['path'], 'eval', code],
        user=site['uid'], group=site['gid'], extra_groups=[],
        env={**os.environ, 'HOME': site['home']}, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Site-owner WP-CLI failed: ' + result.stderr)
    return json.loads(result.stdout)


def write_fixture(owner, path, text):
    subprocess.run(['python3', '-c',
        'from pathlib import Path;import sys;'
        'p=Path(sys.argv[1]);p.parent.mkdir(exist_ok=True);'
        'f=p.open("x");f.write(sys.argv[2]);f.close()', str(path), text],
        user=owner['uid'], group=owner['gid'], extra_groups=[], check=True)
    fixtures.append((owner, path))


def call(action, **values):
    return engine.action(dict(actor='root', admin=True, action=action, **values))


def check(ok, label):
    if not ok:
        raise AssertionError(label)
    if label not in checks:
        checks.append(label)


def request(owner, jar, path, data=None, headers=None):
    url = urllib.parse.urljoin('http://' + owner['domain'], path)
    parsed = urllib.parse.urlsplit(url)
    if parsed.hostname != owner['domain'] or parsed.scheme != 'http':
        raise ValueError('Unexpected fixture URL')
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers or {})
    jar.add_cookie_header(req)
    conn = http.client.HTTPConnection(args.address, timeout=30)
    h = {'Host': owner['domain'], **dict(req.header_items())}
    if body is not None:
        h['Content-Type'] = 'application/x-www-form-urlencoded'
    conn.request('POST' if body is not None else 'GET',
                 parsed.path + ('?' + parsed.query if parsed.query else ''), body, h)
    response = conn.getresponse()
    raw = response.read()
    jar.extract_cookies(response, req)
    status = response.status
    h = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    if status != 200:
        raise AssertionError('Unexpected HTTP ' + str(status) + ' for ' + parsed.path)
    return h, raw.decode('utf-8', 'replace')


def session(jar, mode='inspect'):
    h, body = request(site, jar, '/?wc-ajax=' + hook,
                      {'mode': mode}, {'X-WVW-Test-Key': key})
    check(h.get('x-webuzo-varnish') == 'PASS', 'Session fixture bypasses shared cache')
    return json.loads(body)


fixed = [Path('/usr/local/apps/nginx/etc/nginx.conf'),
         Path('/usr/local/apps/nginx/etc/conf.d/proxy.conf'),
         Path('/usr/local/apps/apache2/etc/httpd.conf')]
hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}
try:
    metadata = wp("echo wp_json_encode(array('woo'=>defined('WC_VERSION')?WC_VERSION:null,'theme'=>get_stylesheet()));")
    if not metadata['woo'] or metadata['theme'] != 'storefront':
        raise ValueError('Activate WooCommerce and Storefront on the disposable first site')
    product = wp("$p=new WC_Product_Simple();$p->set_name('Cache session test " + identity + "');"
                 "$p->set_status('publish');$p->set_regular_price('100');$p->set_virtual(true);$p->save();"
                 "echo wp_json_encode(array('id'=>$p->get_id(),'url'=>get_permalink($p->get_id())));")
    callback = """<?php
add_action('wc_ajax_HOOK', function () {
    if (!hash_equals('KEY', $_SERVER['HTTP_X_WVW_TEST_KEY'] ?? '')) { status_header(403); exit; }
    if (!WC()->session || !WC()->cart) { wc_load_cart(); }
    WC()->session->set('wvw_test_session', true);
    if (($_POST['mode'] ?? '') === 'notice') { wc_add_notice('MARKER', 'notice'); }
    WC()->session->set_customer_session_cookie(true);
    nocache_headers();
    wp_send_json(array('count'=>WC()->cart->get_cart_contents_count(),'notices'=>wc_notice_count()));
});
""".replace('HOOK', hook).replace("'KEY'", "'" + key + "'").replace('MARKER', marker)
    write_fixture(site, Path(site['path']) / 'wp-content/mu-plugins' / ('wvw-session-' + identity + '.php'), callback)
    control_path = '/wvw-session-control-' + identity + '.php'
    write_fixture(other, Path(other['path']) / control_path[1:],
                  "<?php header('Content-Type: text/html'); header('Cache-Control: public, max-age=300'); echo 'control';")
    call('configure', id=site['id'], profile='woocommerce', enabled=True,
         ttl=site['ttl'], bypass=site['bypass'])
    call('purge', id=site['id'])
    empty = http.cookiejar.CookieJar()
    request(other, empty, control_path)
    h, control = request(other, empty, control_path)
    check(h.get('x-webuzo-varnish') == 'HIT', 'Control account has a warm public object')
    anonymous = http.cookiejar.CookieJar()
    h, public = request(site, anonymous, product['url'])
    h, public = request(site, anonymous, product['url'])
    check(h.get('x-webuzo-varnish') == 'HIT', 'Anonymous product gets HIT without another WordPress integration')
    alice, bob = http.cookiejar.CookieJar(), http.cookiejar.CookieJar()
    session(alice); session(bob)
    h, _ = request(site, alice, product['url'])
    check(h.get('x-webuzo-varnish') == 'PASS', 'Persistent Woo session bypasses a warm public object')
    h, _ = request(site, alice, product['url'], {'add-to-cart': product['id'], 'quantity': 1})
    check(h.get('x-webuzo-varnish') == 'PASS', 'Actual add-to-cart POST bypasses cache')
    check(session(alice)['count'] == 1 and session(bob)['count'] == 0, 'Actual Woo carts are independent')
    for cookie in list(alice):
        if cookie.name in ('woocommerce_items_in_cart', 'woocommerce_cart_hash'):
            alice.clear(cookie.domain, cookie.path, cookie.name)
    h, _ = request(site, alice, product['url'])
    check(h.get('x-webuzo-varnish') == 'PASS' and session(alice)['count'] == 1,
          'Persistent cart survives lost cart markers without getting cached empty HTML')
    check(any(c.name == 'woocommerce_items_in_cart' for c in alice), 'Origin restores missing cart markers')
    notice = http.cookiejar.CookieJar()
    session(notice, 'notice')
    check(not any(c.name in ('woocommerce_items_in_cart', 'woocommerce_cart_hash') for c in notice),
          'Real Woo notice exists without cart marker cookies')
    call('purge', id=site['id'])
    h, personal = request(site, notice, product['url'])
    check(h.get('x-webuzo-varnish') == 'PASS' and marker in personal, 'Notice is rendered only in an uncached origin response')
    h, second = request(site, bob, product['url'])
    check(h.get('x-webuzo-varnish') == 'PASS' and marker not in second, 'Another guest cannot receive the first guest notice')
    h, final_public = request(site, anonymous, product['url'])
    h, final_public = request(site, anonymous, product['url'])
    check(h.get('x-webuzo-varnish') == 'HIT' and marker not in final_public, 'Personal notice did not enter anonymous shared cache')
    h, body = request(other, empty, control_path)
    check(h.get('x-webuzo-varnish') == 'HIT' and body == control, 'Other account cache remains unchanged')
    check(hashes == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}, 'Native factory configuration files unchanged')
finally:
    try:
        call('configure', id=original['id'], profile=original['profile'], enabled=original['enabled'],
             ttl=original['ttl'], bypass=original['bypass'])
    finally:
        for owner, path in reversed(fixtures):
            subprocess.run(['python3', '-c', 'from pathlib import Path;import sys;Path(sys.argv[1]).unlink(missing_ok=True)', str(path)],
                           user=owner['uid'], group=owner['gid'], extra_groups=[], check=True)
        if product:
            wp('wp_delete_post(' + str(int(product['id'])) + ',true);echo "{}";')
        call('purge', id=site['id'])
        call('purge', id=other['id'])
print(json.dumps(dict(environment=metadata, passed=len(checks), checks=checks), indent=2))
