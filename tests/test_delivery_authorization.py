"""Adapter compilation checks for the existing per-site prepare credential.

Native endpoint authentication and non-HTTP connection acceptance are separate.
"""
import copy
import contextlib
import os
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
import types

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'shared')]


def render_sites():
    if (ROOT/'src/vcl.py').is_file():
        from vcl import render
        site=dict(id='a'*32,aliases=[],profile='ultracache',token='A'*32,
            enabled=True,suspended=False,custom_recv='',custom_backend_response='')
        sites={}
        for name,identity,profile,enabled in (
            ('first.test','a','ultracache',True),('second.test','b','ultracache',True),
            ('basic.test','c','basic',True),('disabled.test','d','ultracache',False)):
            value=copy.deepcopy(site);value.update(id=identity*32,token=identity.upper()*32,
                profile=profile,enabled=enabled);sites[name]=value
        return render(dict(owners=dict(owner=dict(enabled=True,suspended=False,package='default',sites=sites))),
            dict(origin_ip='127.0.0.1',origin_port=8080)), 'X-HVH-Site',32
    sites={}
    for name,identity,profile,enabled in (
        ('first.test','a','ultracache',True),('second.test','b','ultracache',True),
        ('basic.test','c','basic',True),('disabled.test','d','ultracache',False)):
        sites[identity*32]=dict(id=identity*32,domain=name,names=[name],enabled=enabled,error='',
            token=identity*64,bypass=[],recv_vcl='',backend_vcl='',profile=profile)
    # Pure source rendering never calls POSIX account or locking APIs. Permit importing
    # the unchanged production native.hostname validator on Windows only;
    # this shim is not a Webuzo inventory/runtime qualification.
    imports=patch.dict(sys.modules,{n:types.ModuleType(n) for n in ('pwd','grp','fcntl')}) if os.name=='nt' else contextlib.nullcontext()
    with imports:
        import policy
        source=policy.render(sites,'e'*64,'f'*64)
    return source,'X-WV-Site',64


class DeliveryAuthorization(unittest.TestCase):
    def test_only_active_ultracache_sites_have_backend_owned_tokens(self):
        source,header,size=render_sites()
        body=re.search(r'sub scp_delivery_authorization \{(.*?)\n\}',source,re.S).group(1)
        self.assertNotIn('@@',source)
        for identity in ('a','b'):
            token=identity.upper()*size if size==32 else identity*size
            expected='if (bereq.http.'+header+' == "'+identity*32+'") { set bereq.http.X-UltraCache-Delivery-Authorization = "'+token+'"; }'
            self.assertIn(expected,body)
        for identity in ('c','d'):self.assertNotIn(identity*32,body)
        self.assertEqual(source.count('set bereq.http.X-UltraCache-Delivery-Authorization ='),2)
        for scope in ('req','beresp','resp'):
            self.assertFalse('set '+scope+'.http.X-UltraCache-Delivery-Authorization =' in source,
                'Credential assignment must be backend-only')

    def test_call_requires_owned_prepare_and_external_or_echo_fields_are_stripped(self):
        source,_,_=render_sites()
        branch=source.split('if (cookie_handoff.delivery_backend()) {',1)[1].split('} else {',1)[0]
        self.assertIn('call scp_delivery_authorization;',branch)
        self.assertIn('Delivery credential unavailable',branch)
        self.assertEqual(source.count('call scp_delivery_authorization;'),1)
        for scope in ('req','bereq','beresp','resp'):
            self.assertIn('unset '+scope+'.http.X-UltraCache-Delivery-Authorization;',source)


if __name__=='__main__':unittest.main()
