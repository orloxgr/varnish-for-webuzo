"""Webuzo adapter for the panel-independent native HTTP parity suite."""
import argparse
import json
from test_profiles import program

parser=argparse.ArgumentParser();parser.add_argument('--profile',required=True);parser.add_argument('--legacy-cookie-delivery')
parser.add_argument('--site-settings')
args=parser.parse_args()
legacy=json.loads(args.legacy_cookie_delivery) if args.legacy_cookie_delivery else None
settings=json.loads(args.site_settings) if args.site_settings else None
if settings is not None and (not isinstance(settings,dict) or set(settings)-{'aggressive','aggressive_ttl','cms_installations','cookie_policies','bypass','cms_cookies'}):parser.error('Invalid parity site settings')
print(json.dumps(dict(vcl=program(args.profile,legacy_cookie_delivery=legacy,site_settings=settings),get_headers={'X-WV-Gateway':'e'*64},purge_headers={'X-UltraCache-Token':'b'*64})))
