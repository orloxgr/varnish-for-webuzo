"""Panel-independent CMS route descriptors and VCL generation.

Adapters discover installations under their native document roots. Descriptors
contain URL paths only, never PHP source, credentials or administrator VCL.
"""
import json
import re
from urllib.parse import quote, unquote

NAMES = ('wordpress', 'joomla', 'drupal', 'magento', 'prestashop')
SOURCES = {
    'wordpress': 'https://github.com/woocommerce/woocommerce/tree/trunk/plugins/woocommerce/includes',
    'joomla': 'https://github.com/joomla/joomla-cms/blob/5.4-dev/components/com_users/src/Service/Router.php',
    'drupal': 'https://github.com/drupal/drupal/blob/11.x/core/modules/user/user.routing.yml',
    'magento': 'https://github.com/magento/magento2/blob/2.4/app/code/Magento/PageCache/etc/varnish6.vcl',
    'prestashop': 'https://github.com/PrestaShop/PrestaShop/tree/9.0.0/controllers/front',
}

# Match complete route segments, not substrings such as /cartoon or /accounting.
ROUTES = {
    'wordpress': r'(?:wp-admin|wp-login[.]php|xmlrpc[.]php|wp-cron[.]php|wp-comments-post[.]php|cart|checkout|my-account|wc-api)',
    'joomla': r'(?:administrator|component/users|component/(?:virtuemart|hikashop)/(?:cart|checkout|user|order)|(?:login|logout|registration|reset|remind|profile))',
    'drupal': r'(?:admin|user/(?:login|login_status|logout|register|password|reset|edit)|user/[0-9]+/(?:edit|cancel)|node/(?:add|[0-9]+/(?:edit|delete))|(?:cart|checkout))',
    'magento': r'(?:admin|customer|checkout|sales/order|sales/guest|wishlist|paypal|multishipping|vault|customer/section/load)',
    'prestashop': r'(?:authentication|login|logout|password|my-account|identity|addresses|address|history|order-detail|order-follow|order-slip|cart|order|order-confirmation|guest-tracking)',
}
QUERIES = {
    'wordpress': [r'(^|&)(?:add-to-cart|remove_item|undo_item|wc-ajax|wc-api|apply_coupon|remove_coupon|order_again|cancel_order|pay_for_order|download_file)=', r'(^|&)key=wc_order_'],
    'joomla': [r'(^|&)option=com_users(?:&|$)', r'(^|&)task=(?:user[.](?:login|logout)|profile[.]save|registration[.]register|reset[.][^&]*|remind[.][^&]*|article[.](?:edit|save|cancel))(?:&|$)', r'(^|&)layout=edit(?:&|$)', r'(^|&)option=com_(?:virtuemart|hikashop)(?:&|$).*'],
    'drupal': [r'(^|&)q=(?:admin|user/(?:login|logout|register|password|reset|edit)|node/(?:add|[0-9]+/(?:edit|delete)))(?:/|&|$)', r'(^|&)(?:form_build_id|form_token)='],
    'magento': [],
    'prestashop': [r'(^|&)controller=(?:authentication|password|my-account|identity|addresses|address|history|order-detail|order-follow|order-slip|cart|order|order-confirmation|guest-tracking)(?:&|$)', r'(^|&)(?:add|delete|update|submitLogin|submitAccount|submitMessage)='],
}


def path(value):
    if not isinstance(value, str) or not value.startswith('/') or re.search(r'%(?![0-9a-fA-F]{2})', value):
        raise ValueError('Invalid CMS URL path')
    decoded = unquote(value, errors='strict')
    if any(ord(c) < 32 or ord(c) == 127 or c in '?#!\\' for c in decoded) or any(p in ('.', '..') for p in decoded.split('/')):
        raise ValueError('Invalid CMS URL path')
    return quote(decoded, safe='/-._~').rstrip('/') or '/'


def normalize(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError('CMS installations must be a list')
    rows = []
    for row in value:
        if not isinstance(row, dict) or set(row) - {'cms', 'base', 'private_paths', 'private_queries'} or row.get('cms') not in NAMES:
            raise ValueError('Invalid CMS installation')
        result = dict(cms=row['cms'], base=path(row.get('base', '/')))
        paths = row.get('private_paths', [])
        if not isinstance(paths, list):
            raise ValueError('CMS private paths must be a list')
        result['private_paths'] = sorted(set(path(p) for p in paths))
        queries = row.get('private_queries', [])
        if not isinstance(queries, list):
            raise ValueError('CMS private queries must be a list')
        result['private_queries'] = []
        for query in queries:
            if (not isinstance(query, dict) or not {'name','value'} <= set(query) or set(query)-{'name','value','base'} or
                not isinstance(query['name'], str) or not re.fullmatch('[A-Za-z0-9_.-]+', query['name']) or
                not isinstance(query['value'], str) or not query['value'] or
                re.search(r'[\x00-\x20\x7f&=#]', query['value'])):
                raise ValueError('Invalid CMS private query')
            if query not in result['private_queries']:
                result['private_queries'].append(dict(query))
                if 'base' in query:result['private_queries'][-1]['base']=path(query['base'])
        if result not in rows:
            rows.append(result)
    return sorted(rows, key=lambda row: (-len(row['base']), row['base'], row['cms']))


def _quote(value):
    return json.dumps(value, ensure_ascii=False)


def _regex(value):
    # VCL long strings preserve PCRE escapes. Literal descriptor paths have
    # their braces escaped before reaching this function.
    if '"}' in value:
        raise ValueError('Invalid CMS match delimiter')
    return '{"' + value + '"}'


def _path_regex(value):
    # Request matching decodes ASCII escapes; UTF-8 escapes remain encoded.
    scratch = re.sub(r'%([0-7][0-9a-fA-F])', lambda m: chr(int(m[1], 16)) if int(m[1],16) not in (34,92) else m[0], value)
    return '(?:' + '|'.join(sorted({re.escape(scratch), re.escape(unquote(value))})) + ')'


def literal_prefixes(value):
    if not isinstance(value, list):
        raise ValueError('Bypass paths must be a list')
    result = []
    for item in value:
        path(item)
        canonical = quote(unquote(item, errors='strict'), safe='/-._~')
        if canonical not in result:
            result.append(canonical)
    return result


def compile_custom_recv(value, reason='site-bypass-path'):
    if reason not in ('site-bypass-path', 'custom-private-path'):
        raise ValueError('Invalid bypass diagnostic')
    code = []
    for item in literal_prefixes(value):
        pattern = '(?i)^(?:' + re.escape(item) + '|' + re.escape(unquote(item)) + ')'
        code.append('if (req.url ~ ' + _regex(pattern) + ') { set req.http.X-SCP-Reason = ' + _quote(reason) + '; return (pass); }')
    return '\n'.join(code)


def compile_recv(value):
    """Called with a normalized COPY of the path/query; origin URL is untouched."""
    code = []
    rows=normalize(value)
    for row in rows:
        # Configured public aliases may lie outside the CMS core directory
        # (WordPress siteurl=/wordpress, home=/ is a common installation).
        for configured in row['private_paths']:
            code.append('if (req.http.X-SCP-CMS-Path ~ ' + _regex('(?i)^' + _path_regex(configured) + r'(?:/|$)') + ') { set req.http.X-SCP-Reason = ' + _quote(row['cms'] + '-private-route') + '; return (pass); }')
        for query in row['private_queries']:
            pattern = '(?i)(^|&)' + re.escape(query['name']) + '=' + re.escape(query['value']) + '(&|$)'
            condition='req.http.X-SCP-CMS-Query ~ '+_regex(pattern)
            if 'base' in query:
                scope='' if query['base']=='/' else _path_regex(query['base'])
                condition+=' && req.http.X-SCP-CMS-Path ~ '+_regex('(?i)^'+scope+r'(?:/|$)')
                for other in rows:
                    if other!=row and other['base']!='/' and (query['base']=='/' or other['base'].startswith(query['base']+'/')):
                        condition+=' && req.http.X-SCP-CMS-Path !~ '+_regex('(?i)^'+_path_regex(other['base'])+r'(?:/|$)')
            code.append('if ('+condition+') { set req.http.X-SCP-Reason = ' + _quote(row['cms'] + '-private-route') + '; return (pass); }')
        base = '' if row['base'] == '/' else _path_regex(row['base'])
        # Longest installation base wins; a parent CMS never captures a child.
        scope = '(?i)^' + base + r'(?:/|$)'
        root = '(?i)^' + base + r'/(?:[a-z]{2,3}(?:-[a-z0-9]{2,8})?/)?(?:index[.]php/)?'
        code.append('if (!req.http.X-SCP-CMS && req.http.X-SCP-CMS-Path ~ ' + _regex(scope) + ') {')
        code.append('set req.http.X-SCP-CMS = ' + _quote(row['cms']) + ';')
        checks = ['req.http.X-SCP-CMS-Path ~ ' + _regex(root + ROUTES[row['cms']] + r'(?:/|$)')]
        if row['cms'] == 'drupal':
            checks.append('req.http.X-SCP-CMS-Path ~ ' + _regex(root + r'user/?$'))
        checks.extend('req.http.X-SCP-CMS-Query ~ ' + _regex('(?i)' + expression) for expression in QUERIES[row['cms']])
        # Component browsing remains cacheable: only commerce actions/views pass.
        if row['cms'] == 'joomla':
            checks.pop()  # Replace the broad option expression with an action pair.
            checks.append('(req.http.X-SCP-CMS-Query ~ "(?i)(^|&)option=com_(virtuemart|hikashop)(&|$)" && req.http.X-SCP-CMS-Query ~ "(?i)(^|&)(view|task|ctrl)=(cart|checkout|user|order)([.]|&|$)")')
        code.append('if (' + ' ||\n'.join(checks) + ') { set req.http.X-SCP-Reason = ' + _quote(row['cms'] + '-private-route') + '; return (pass); }')
        code.append('}')
    return '\n'.join(code)


def normalization_vcl():
    """Decode ASCII escapes for matching only; never modify the actual request."""
    code = ['sub scp_cms_normalize {', 'set req.http.X-SCP-CMS-Path = regsub(req.url, "[?].*$", "");',
            'set req.http.X-SCP-CMS-Query = req.http.X-SCP-Query;']
    for header in ('Path', 'Query'):
        code.append('if (req.http.X-SCP-CMS-' + header + ' ~ "%[0-9a-fA-F]{2}") {')
        # Decode %25 last: one decoding pass, including escaped path separators.
        for number in [*range(32, 37), *range(38, 127), 37]:
            char = chr(number)
            if char in '"\\' or header == 'Query' and char in '&=?#':
                continue
            code.append('set req.http.X-SCP-CMS-' + header + ' = regsuball(req.http.X-SCP-CMS-' + header + ', "(?i)%' + format(number, '02x') + '", ' + _quote(char) + ');')
        code.append('}')
    code.append('}')
    return '\n'.join(code)
