"""Literal PHP settings and read-only CMS URL metadata, without CMS bootstrap.

The adapter supplies a SELECT-only query callback and handles native account
identity/database transport. This module never logs credentials or executes PHP.
"""
import re
from urllib.parse import parse_qs, unquote, urlsplit

from cms_discovery import read_literal
from cms_routes import normalize, path

TOKEN = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|/\*[\s\S]*?\*/|//[^\r\n]*|\#[^\r\n]*|[A-Za-z_][A-Za-z0-9_]*|=>|[^\s]", re.S)


class MetadataUnavailable(ValueError):
    pass


def literal(token):
    if len(token) < 2 or token[0] not in "'\"" or token[-1] != token[0]:
        raise MetadataUnavailable('CMS setting is not a literal string')
    quote, body = token[0], token[1:-1]
    result, i = [], 0
    escapes = {'n':'\n', 'r':'\r', 't':'\t', 'v':'\v', 'e':'\x1b', 'f':'\f', '\\':'\\', '"':'"', '$':'$'}
    while i < len(body):
        char = body[i]
        if quote == '"' and char == '$':
            raise MetadataUnavailable('Dynamic CMS settings are not evaluated')
        if char == '\\' and i + 1 < len(body):
            following = body[i+1]
            if following in ('\\', "'") and quote == "'":
                result.append(following); i += 2; continue
            if quote == '"':
                if following in escapes:
                    result.append(escapes[following]); i += 2; continue
                if following.isdigit() or following in 'xXuU':
                    raise MetadataUnavailable('Encoded CMS literals require a supported static representation')
        result.append(char); i += 1
    return ''.join(result)


def settings(text):
    tokens = [token for token in TOKEN.findall(text) if not token.startswith(('//', '/*', '#'))]
    constants, variables, entries = {}, {}, {}
    conflicts = set()
    def save(target, name, value):
        key = (id(target), name)
        if key in conflicts:return
        if name in target and target[name] != value:
            target.pop(name)
            conflicts.add(key)
            return
        target[name] = value
    for i, token in enumerate(tokens):
        try:
            if token.lower() == 'define' and tokens[i+1] == '(' and tokens[i+3] == ',' and tokens[i+5] == ')':
                save(constants, literal(tokens[i+2]), literal(tokens[i+4]))
            elif token == '$' and tokens[i+2] == '=' and tokens[i+4] == ';':
                save(variables, tokens[i+1], literal(tokens[i+3]))
            elif token[:1] in "'\"" and tokens[i+1] == '=>':
                save(entries, literal(token), literal(tokens[i+2]))
        except (IndexError, MetadataUnavailable):
            # Dynamic/unrelated expressions are not executed or guessed. A
            # required missing key is reported by connection(), without values.
            continue
    return constants, variables, entries


def connection(cms, root):
    if cms == 'wordpress':
        try:
            text = read_literal(root, 'wp-config.php')
        except FileNotFoundError:
            from pathlib import Path
            text = read_literal(Path(root).parent, 'wp-config.php')
        constants, variables, _ = settings(text)
        mapping = dict(host='DB_HOST', user='DB_USER', password='DB_PASSWORD', database='DB_NAME')
        values = {key:constants.get(name) for key,name in mapping.items()}
        values['prefix'] = variables.get('table_prefix')
    elif cms == 'joomla':
        _, variables, _ = settings(read_literal(root, 'configuration.php'))
        values = {key:variables.get(name) for key,name in dict(host='host', user='user', password='password', database='db', prefix='dbprefix').items()}
    elif cms == 'prestashop':
        try:
            _, _, entries = settings(read_literal(root, 'app/config/parameters.php'))
            values = {key:entries.get('database_'+name) for key,name in dict(host='host', user='user', password='password', database='name', prefix='prefix').items()}
            port = entries.get('database_port')
            if port:
                values['port'] = port
        except FileNotFoundError:
            constants, _, _ = settings(read_literal(root, 'config/settings.inc.php'))
            values = {key:constants.get(name) for key,name in dict(host='_DB_SERVER_',user='_DB_USER_',password='_DB_PASSWD_',database='_DB_NAME_',prefix='_DB_PREFIX_').items()}
    else:
        raise MetadataUnavailable('No database route reader for this CMS')
    if any(not isinstance(values.get(key), str) for key in ('host','user','password','database','prefix')):
        raise MetadataUnavailable('Required literal CMS database settings were not found')
    if not re.fullmatch('[A-Za-z0-9_]*', values['prefix']):
        raise MetadataUnavailable('Unsupported CMS database prefix')
    host = values['host']
    if ':/' in host and not host.startswith('['):
        host, socket = host.split(':', 1)
        values['socket'] = socket
    elif host.startswith('['):
        match = re.fullmatch(r'\[([^]]+)\](?::([0-9]+))?', host)
        if not match:
            raise MetadataUnavailable('Unsupported CMS database host')
        host = match[1]
        if match[2]:values['port'] = match[2]
    elif host.count(':') == 1 and host.rsplit(':', 1)[1].isdigit():
        host, values['port'] = host.rsplit(':', 1)
    values['host'] = host
    if values.get('port') is not None:
        try:values['port'] = int(values['port'])
        except (ValueError, TypeError):raise MetadataUnavailable('Invalid CMS database port') from None
        if not 1 <= values['port'] <= 65535:raise MetadataUnavailable('Invalid CMS database port')
    if any('\x00' in str(value) or '\n' in str(value) or '\r' in str(value) for key,value in values.items() if key != 'password'):
        raise MetadataUnavailable('Invalid literal CMS database setting')
    return values


def _joomla_private(link):
    query = parse_qs(urlsplit(link).query)
    option = query.get('option', [''])[0]
    if option == 'com_users':return True
    if option == 'com_content' and (query.get('view') == ['form'] or query.get('layout') == ['edit']):return True
    return option in ('com_virtuemart','com_hikashop') and any(query.get(name, [''])[0] in ('cart','checkout','user','order') for name in ('view','task','ctrl'))


def aliases(row, query, prefix, hosts):
    """Return a normalized descriptor using trusted, fixed SELECT statements."""
    if not re.fullmatch('[A-Za-z0-9_]*', prefix):raise MetadataUnavailable('Invalid CMS table prefix')
    row = normalize([row])[0]
    private = row['private_paths']
    identities = row['private_queries']
    cms = row['cms']
    if cms == 'wordpress':
        names = ('home','woocommerce_cart_page_id','woocommerce_checkout_page_id','woocommerce_myaccount_page_id')
        options = {r['name']:r['value'] for r in query("SELECT JSON_OBJECT('name',option_name,'value',option_value) FROM `"+prefix+"options` WHERE option_name IN ("+','.join("'"+name+"'" for name in names)+')')}
        home = urlsplit(options.get('home',''))
        if home.scheme not in ('http','https') or home.hostname not in hosts:
            raise MetadataUnavailable('WordPress public home does not belong to this native site')
        base = home.path.rstrip('/')
        posts = {}
        def post(number):
            if number not in posts:
                records = query("SELECT JSON_OBJECT('id',ID,'slug',post_name,'parent',post_parent) FROM `"+prefix+"posts` WHERE ID="+str(number)+" AND post_type='page'")
                posts[number] = records[0] if records else None
            return posts[number]
        for name in names[1:]:
            value = str(options.get(name,''))
            if not value.isdigit() or int(value) <= 0:continue
            number = int(value)
            identities.append(dict(name='page_id',value=str(number),base=path(base or '/')))
            segments, seen = [], set()
            while number:
                if number in seen:raise MetadataUnavailable('Recursive WordPress page hierarchy')
                seen.add(number)
                page = post(number)
                if not page:break
                segments.insert(0,str(page['slug']))
                number = int(page['parent'])
            if segments and number == 0:private.append(path(base+'/'+'/'.join(segments)))
    elif cms == 'joomla':
        languages = {r['language']:r['sef'] for r in query("SELECT JSON_OBJECT('language',lang_code,'sef',sef) FROM `"+prefix+"languages` WHERE published=1")}
        menus = query("SELECT JSON_OBJECT('id',id,'path',path,'link',link,'language',language) FROM `"+prefix+"menu` WHERE client_id=0 AND published=1 AND type='component'")
        for menu in menus:
            if not _joomla_private(menu['link']):continue
            if str(menu['id']).isdigit():identities.append(dict(name='Itemid',value=str(menu['id']),base=row['base']))
            route = str(menu['path']).strip('/')
            if not route:continue
            base = row['base'].rstrip('/')
            private.append(path(base+'/'+route))
            prefixes = languages.values() if menu['language'] == '*' else [languages.get(menu['language'])]
            for language in prefixes:
                if language:private.append(path(base+'/'+str(language).strip('/')+'/'+route))
    elif cms == 'prestashop':
        pages = ('authentication','password','my-account','identity','addresses','address','history','order-detail','order-follow','order-slip','cart','order','order-confirmation','guest-tracking')
        records = query("SELECT JSON_OBJECT('page',m.page,'path',ml.url_rewrite,'language',l.iso_code) FROM `"+prefix+"meta` m JOIN `"+prefix+"meta_lang` ml ON ml.id_meta=m.id_meta JOIN `"+prefix+"lang` l ON l.id_lang=ml.id_lang WHERE m.page IN ("+','.join("'"+name+"'" for name in pages)+')')
        base = row['base'].rstrip('/')
        for record in records:
            if record['path']:
                private.append(path(base+'/'+str(record['path']).strip('/')))
                private.append(path(base+'/'+str(record['language']).strip('/')+'/'+str(record['path']).strip('/')))
    return normalize([row])[0]
