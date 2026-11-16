"""Webuzo adapter for the panel-independent native HTTP parity suite."""
import argparse
import json
from test_profiles import program

parser=argparse.ArgumentParser();parser.add_argument('--profile',required=True);parser.add_argument('--cookie-delivery')
args=parser.parse_args()
delivery=json.loads(args.cookie_delivery) if args.cookie_delivery else None
print(json.dumps(dict(vcl=program(args.profile,cookie_delivery=delivery),get_headers={'X-WV-Gateway':'e'*64},purge_headers={'X-UltraCache-Token':'b'*64})))
