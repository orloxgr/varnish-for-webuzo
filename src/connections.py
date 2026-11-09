"""Local HTTP application connection, scoped by the existing site purge token."""
import http.client
from pathlib import Path
import re
import secrets
import socket
import time
import timeouts

HOST='127.0.0.1'
DEFAULT_PORT=82
READY_PATH='/__webuzo-varnish-connection'


def port(value):
    if type(value) is not int or not 1<=value<1024:
        raise ValueError('Use a local HTTP connection port from 1 to 1023')
    # A hosting user must not be able to impersonate this endpoint while Nginx
    # is stopped and collect another account's site token.
    threshold=int(Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text().strip())
    if value>=threshold:
        raise ValueError('The HTTP connection port must require privileged binding under the existing system policy')
    return value


def prepare(previous,config,value):
    value=port(value)
    if not previous.get('installed') or previous.get('control_port')!=value:
        with socket.socket() as listener:
            try:listener.bind((HOST,value))
            except OSError:raise ValueError('Local HTTP connection port '+str(value)+' is already in use; choose another port') from None
    config['control_port']=value
    config['control_marker']=config.get('control_marker') or secrets.token_hex(16)


def render(config):
    if not config.get('control_port'):return ''
    value=port(config['control_port']);marker=config.get('control_marker','')
    if not re.fullmatch('[0-9a-f]{32}',marker):raise ValueError('Invalid HTTP connection identity')
    allowances=timeouts.settings(config)
    return '''
# Local application HTTP connection. Website traffic keeps its Unix transport.
server {
 listen 127.0.0.1:'''+str(value)+''';
 server_name _;
 access_log off;
 location = '''+READY_PATH+''' {
  if ($request_method != GET) { return 405; }
  add_header X-Webuzo-Varnish-Connection "'''+marker+'''" always;
  return 204;
 }
 location / {
  if ($request_method !~ ^(HEAD|PURGE|BAN)$) { return 405; }
  set $wv_control_token $http_x_webuzo_varnish_token;
  if ($wv_control_token = "") { set $wv_control_token $http_x_ultracache_token; }
  proxy_pass http://unix:/run/varnish-for-webuzo-cache/frontend.sock:;
  proxy_cache off;
  proxy_http_version 1.1;
  proxy_set_header Connection "";
  proxy_set_header Host $http_host;
  proxy_set_header X-Webuzo-Varnish-Token "";
  proxy_set_header X-UltraCache-Token $wv_control_token;
  proxy_set_header X-WV-Control-Discovery "1";
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_connect_timeout '''+timeouts.seconds(allowances['connect'])+''';
  proxy_read_timeout '''+timeouts.seconds(allowances['read'])+''';
  proxy_send_timeout '''+timeouts.seconds(allowances['send'])+''';
  proxy_next_upstream off;
 }
}
'''


def available(config):
    value=config.get('control_port');marker=config.get('control_marker')
    if not value or not marker:return False
    client=http.client.HTTPConnection(HOST,port(value),timeout=1)
    try:
        client.request('GET',READY_PATH)
        response=client.getresponse();response.read()
        return response.status==204 and response.getheader('X-Webuzo-Varnish-Connection')==marker
    except (OSError,http.client.HTTPException):return False
    finally:client.close()


def wait(config):
    if not config.get('control_port'):return
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        if available(config):return
        time.sleep(.1)
    raise RuntimeError('The local HTTP connection did not become ready; previous configuration will be restored')


def details(site,config):
    value=config.get('control_port')
    return dict(domain=site['domain'],names=site['names'],enabled=site['enabled'],profile=site['profile'],
        mode='HTTP',host=HOST,port=value,endpoint='http://'+HOST+':'+str(value) if value else '',
        ready=available(config),header='X-Webuzo-Varnish-Token',key=site['token'])
