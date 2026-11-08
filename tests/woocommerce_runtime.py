"""Actual WooCommerce session isolation on two disposable Webuzo accounts.

Requires WooCommerce and Storefront already active on the first site. Creates
two temporary catalog products. Guest state and errors are produced exclusively
through WooCommerce's existing public endpoints. No test callback is installed.
"""
import argparse
import copy
import hashlib
import html
import http.client
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
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
products = []
checks = []


def wp(code):
    result = subprocess.run(
        [args.php, '-d', 'memory_limit=512M', args.wp, '--path=' + site['path'], 'eval', code],
        user=site['uid'], group=site['gid'], extra_groups=[],
        env={**os.environ, 'HOME': site['home']}, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Site-owner WP-CLI failed: ' + result.stderr)
    return json.loads(result.stdout)


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


def ajax(jar, action, **values):
    h, body = request(site, jar, '/?wc-ajax=' + action, values)
    check(h.get('x-webuzo-varnish') == 'PASS', 'Public Woo AJAX writes bypass shared cache')
    return json.loads(body)


def fragments(value):
    return ''.join(value.get('fragments', {}).values())


def errors(body):
    return [re.sub(r'\s+', ' ', html.unescape(re.sub('<[^>]*>', ' ', value))).strip()
            for value in re.findall(r'<ul[^>]*class="woocommerce-error"[^>]*>(.*?)</ul>', body, re.S)]


fixed = [Path('/usr/local/apps/nginx/etc/nginx.conf'),
         Path('/usr/local/apps/nginx/etc/conf.d/proxy.conf'),
         Path('/usr/local/apps/apache2/etc/httpd.conf')]
hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}
try:
    metadata = wp("echo wp_json_encode(array('woo'=>defined('WC_VERSION')?WC_VERSION:null,'theme'=>get_stylesheet()));")
    if not metadata['woo'] or metadata['theme'] != 'storefront':
        raise ValueError('Activate WooCommerce and Storefront on the disposable first site')
    for kind in ('stock', 'target'):
        code = "$p=new WC_Product_Simple();$p->set_name('Cache session test " + identity + ' ' + kind + "');"
        code += "$p->set_status('publish');$p->set_regular_price('100');$p->set_virtual(true);"
        if kind == 'stock':
            code += "$p->set_manage_stock(true);$p->set_stock_quantity(1);$p->set_backorders('no');"
        code += "$p->save();echo wp_json_encode(array('id'=>$p->get_id(),'name'=>$p->get_name(),'url'=>get_permalink($p->get_id())));"
        products.append(wp(code))
    stock, target = products
    call('configure', id=site['id'], profile='woocommerce', enabled=True,
         ttl=site['ttl'], bypass=site['bypass'])
    call('purge', id=site['id'])
    empty = http.cookiejar.CookieJar()
    request(other, empty, '/')
    h, control = request(other, empty, '/')
    check(h.get('x-webuzo-varnish') == 'HIT', 'Control account has a warm public object')
    anonymous = http.cookiejar.CookieJar()
    h, public = request(site, anonymous, target['url'])
    h, public = request(site, anonymous, target['url'])
    check(h.get('x-webuzo-varnish') == 'HIT', 'Anonymous product gets HIT without another WordPress integration')
    alice, bob = http.cookiejar.CookieJar(), http.cookiejar.CookieJar()
    added = ajax(alice, 'add_to_cart', product_id=stock['id'], quantity=1)
    check(not added.get('error') and stock['name'] in fragments(added), 'Guest adds a real product through public AJAX')
    key_match = re.search(r'[?&]remove_item=([0-9a-f]+)', html.unescape(fragments(added)))
    if not key_match:
        raise AssertionError('Ordinary mini-cart response did not supply its removal key')
    item_key = key_match[1]
    check(any(c.name == 'woocommerce_items_in_cart' for c in alice), 'WooCommerce creates real cart marker cookies')
    h, _ = request(site, alice, target['url'])
    check(h.get('x-webuzo-varnish') == 'PASS', 'Cart bypasses an existing warm public product')
    check(stock['name'] not in fragments(ajax(bob, 'get_refreshed_fragments')), 'Second guest has an independent empty cart')
    failed = ajax(alice, 'add_to_cart', product_id=stock['id'], quantity=1)
    check(failed.get('error') is True, 'Public AJAX rejects adding more than the available stock')
    removed = ajax(alice, 'remove_from_cart', cart_item_key=item_key)
    check(stock['name'] not in fragments(removed), 'Public AJAX removes the last cart item')
    check(not any(c.name in ('woocommerce_items_in_cart', 'woocommerce_cart_hash') for c in alice),
          'Ordinary removal clears cart marker cookies')
    check(any(c.name.startswith('wp_woocommerce_session_') for c in alice), 'Persistent session survives ordinary cart removal')
    call('purge', id=site['id'])
    h, personal = request(site, alice, target['url'])
    personal_errors = errors(personal)
    check(h.get('x-webuzo-varnish') == 'PASS' and bool(personal_errors), 'Real stock error is rendered in an uncached origin response')
    h, second = request(site, bob, target['url'])
    h, second = request(site, bob, target['url'])
    check(h.get('x-webuzo-varnish') == 'HIT' and not errors(second), 'Other guest gets public HIT without the first guest stock error')
    ajax(alice, 'add_to_cart', product_id=stock['id'], quantity=1)
    for cookie in list(alice):
        if cookie.name in ('woocommerce_items_in_cart', 'woocommerce_cart_hash'):
            alice.clear(cookie.domain, cookie.path, cookie.name)
    h, _ = request(site, alice, target['url'])
    check(h.get('x-webuzo-varnish') == 'PASS' and stock['name'] in fragments(ajax(alice, 'get_refreshed_fragments')),
          'Persistent cart survives lost cart markers without getting cached empty HTML')
    check(any(c.name == 'woocommerce_items_in_cart' for c in alice), 'Origin restores missing cart markers')
    h, final_public = request(site, anonymous, target['url'])
    check(h.get('x-webuzo-varnish') == 'HIT' and not errors(final_public), 'Stock error did not enter anonymous shared cache')
    h, body = request(other, empty, '/')
    check(h.get('x-webuzo-varnish') == 'HIT' and body == control, 'Other account cache remains unchanged')
    check(hashes == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in fixed}, 'Native factory configuration files unchanged')
finally:
    try:
        call('configure', id=original['id'], profile=original['profile'], enabled=original['enabled'],
             ttl=original['ttl'], bypass=original['bypass'])
    finally:
        for product in products:
            wp('wp_delete_post(' + str(int(product['id'])) + ',true);echo "{}";')
        call('purge', id=site['id'])
        call('purge', id=other['id'])
print(json.dumps(dict(environment=metadata, passed=len(checks), checks=checks), indent=2))
