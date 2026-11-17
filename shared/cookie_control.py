"""Authenticated, explicitly configured WordPress cookie-policy control.

No discovery, visitor-time request or WordPress dependency. Native adapters own
transaction journals and call prepare/commit/rollback around their actual apply.
"""
import hashlib
import hmac
import json
import re
import secrets
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from cookie_admin import normalize, resolve

PATH = '/wp-json/ultracache/v1/cookie-policy-control'
HEADER = 'X-UltraCache-Cookie-Control-Signature'
DIGEST_HEADER = 'X-UltraCache-Cookie-Control-Body-SHA256'
PREFIX = 'ultracache-cookie-control-v1'


class ControlError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('utf-8')


def snapshot(central=None, site=None):
    return {'schemaVersion': 1, 'central': normalize(central), 'site': normalize(site)}


def effective_digest(host, policy):
    if (not isinstance(policy, dict) or type(policy.get('schemaVersion')) is not int or
            policy['schemaVersion'] != 1 or set(policy) != {'schemaVersion', 'central', 'site'}):
        raise ValueError('Unsupported scoped cookie snapshot')
    rules = [{key: row[key] for key in ('scope', 'match', 'action')}
             for row in resolve(policy['central'], policy['site'])]
    return hashlib.sha256(canonical({'host': host, 'rules': rules})).hexdigest()


def integration(value, host, aliases=()):
    """Native inventory supplies canonical host/aliases, never a submitted owner."""
    if value is None:
        return {'enabled': False, 'url': 'https://' + host + PATH}
    if not isinstance(value, dict) or set(value) != {'enabled', 'url'} or type(value['enabled']) is not bool:
        raise ValueError('Use an explicit WordPress integration switch and URL')
    url = value['url']
    if not isinstance(url, str):
        raise ValueError('WordPress integration URL must be text')
    if not value['enabled']:
        return {'enabled':False,'url':url or 'https://'+host+PATH}
    parsed = urllib.parse.urlsplit(url)
    # No arbitrary URL paths, credentials, query strings or cross-account hosts.
    # Native inventory is the authority; a user cannot turn this into a root URL
    # fetcher. HTTP permits existing HTTP-only sites; both messages are signed.
    if (not parsed.hostname or parsed.scheme not in ('http', 'https') or parsed.username is not None or parsed.password is not None or
            parsed.hostname not in (host, *aliases) or parsed.path != PATH or parsed.query or parsed.fragment or
            (parsed.port is not None and not 1 <= parsed.port <= 65535)):
        raise ValueError('Use this website’s canonical WordPress control endpoint')
    return {'enabled': value['enabled'], 'url': url}


def reconcile_integration(value, host, aliases=()):
    """Revoke a persisted connection after native ownership changes, without I/O.

    This is inventory reconciliation, never validation of a submitted enabled
    connection. Explicit saves still use integration() against current ownership.
    """
    if value is None or isinstance(value,dict) and value.get('enabled') is False:
        return integration(value,host,aliases),False
    if not isinstance(value,dict) or not isinstance(value.get('url'),str):
        return integration(value,host,aliases),False
    hostname=urllib.parse.urlsplit(value['url']).hostname
    normalized=integration(value,hostname)
    if hostname not in (host,*aliases):
        return dict(normalized,enabled=False),True
    return normalized,False


def cache_contract(value, host, aliases=(), central=None, site=None):
    """Expected origin Vary provenance, not visitor-provided public approval."""
    configured=integration(value,host,aliases)
    if not configured['enabled'] or not any(row['action'] in ('variant','private') for row in resolve(central,site)):
        return ''
    return effective_digest(urllib.parse.urlsplit(configured['url']).hostname,snapshot(central,site))


def request_signature(token, body, host, request_id, expires):
    message = '\n'.join([PREFIX, 'POST', PATH, host, request_id, str(expires), hashlib.sha256(body).hexdigest()])
    return 'v1=' + hmac.new(token.encode(), message.encode(), hashlib.sha256).hexdigest()


def response_signature(token, status, request_id, body):
    return response_digest_signature(token, status, request_id, hashlib.sha256(body).hexdigest())


def response_digest_signature(token, status, request_id, digest):
    message = '\n'.join([PREFIX, 'response', str(status), request_id, digest])
    return 'v1=' + hmac.new(token.encode(), message.encode(), hashlib.sha256).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise ControlError('WordPress cookie control refused an endpoint redirect')


class Client:
    def __init__(self, configuration, host, token, policy, *, request_id=None, aliases=()):
        configured = integration(configuration, host, aliases)
        if not configured['enabled']:
            raise ValueError('Enable this website’s WordPress integration before control requests')
        self.url = configured['url']
        self.host = urllib.parse.urlsplit(self.url).hostname
        if not isinstance(token, str) or not token:
            raise ValueError('WordPress control requires the existing site token')
        self.token = token
        self.policy = snapshot(policy.get('central'), policy.get('site'))
        self.target_digest = effective_digest(self.host, self.policy)
        self.request_id = request_id or secrets.token_hex(16)
        if not re.fullmatch('[0-9a-f]{32}', self.request_id):
            raise ValueError('Invalid WordPress cookie transaction identity')
        self.base_digest = ''

    def call(self, operation):
        if operation not in ('status', 'prepare', 'commit', 'rollback'):
            raise ValueError('Unknown WordPress cookie control operation')
        # The signature lifetime prevents replay. It does not expire a running
        # operation or staged transaction; each control request gets a fresh MAC.
        expires = int(time.time()) + 300
        payload = dict(protocol=1, operation=operation, host=self.host,
                       requestId=self.request_id, expires=expires, baseDigest=self.base_digest, policy=self.policy)
        body = canonical(payload)
        request = urllib.request.Request(self.url, data=body, method='POST', headers={
            'Content-Type': 'application/json',
            HEADER: request_signature(self.token, body, self.host, self.request_id, expires)})
        try:
            try:
                response = urllib.request.build_opener(NoRedirect()).open(request)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.code
                digest = response.headers.get(DIGEST_HEADER, '')
                signature = response.headers.get(HEADER, '')
                # Authenticate the declared body hash before accepting any body
                # bytes. An unsigned origin cannot fill root memory/disk with an
                # untrusted response. Signed data streams without a work ceiling.
                if (not re.fullmatch('[0-9a-f]{64}', digest) or not hmac.compare_digest(signature,
                        response_digest_signature(self.token, status, self.request_id, digest))):
                    raise ControlError('WordPress cookie control response authentication failed (HTTP ' + str(status) + ')')
                actual = hashlib.sha256()
                with tempfile.TemporaryFile() as stream:
                    while chunk := response.read(65536):
                        actual.update(chunk)
                        stream.write(chunk)
                    if not hmac.compare_digest(actual.hexdigest(), digest):
                        raise ControlError('WordPress cookie control response authentication failed')
                    stream.seek(0)
                    result = json.load(stream)
            if (not isinstance(result, dict) or type(result.get('protocol')) is not int or result['protocol'] != 1 or
                    result.get('requestId') != self.request_id or result.get('host') != self.host or
                    result.get('operation') != operation):
                raise ControlError('WordPress cookie control returned a mismatched response')
            if not 200 <= status < 300 or result.get('ok') is not True:
                stage = result.get('stage', 'application')
                if not isinstance(stage, str) or not re.fullmatch('[a-z][a-z-]*', stage):
                    stage = 'application'
                raise ControlError('WordPress cookie control failed at ' + stage + ' (HTTP ' + str(status) + ')')
            active = result.get('activeDigest')
            if not isinstance(active, str) or not re.fullmatch('[0-9a-f]{64}', active):
                raise ControlError('WordPress cookie control did not identify its active snapshot')
            if operation == 'status':
                self.base_digest = active
            elif operation in ('prepare', 'commit') and result.get('targetDigest') != self.target_digest:
                raise ControlError('WordPress cookie control acknowledged a different policy')
            if operation == 'commit' and active != self.target_digest:
                raise ControlError('WordPress cookie control did not activate the requested policy')
            if operation == 'rollback':
                disposition = result.get('rollbackState')
                if disposition not in ('restored','not-applied','superseded'):
                    raise ControlError('WordPress cookie control did not identify the rollback result')
                if disposition == 'restored' and active != self.base_digest:
                    raise ControlError('WordPress cookie control did not restore the previous policy')
            return result
        except ControlError:
            raise
        except (OSError, ValueError, TypeError, urllib.error.URLError):
            raise ControlError('WordPress cookie control transport or response failed') from None
