"""Webuzo adapter for the panel-independent native HTTP parity suite."""
import argparse
import json
from test_profiles import program

parser=argparse.ArgumentParser();parser.add_argument('--profile',required=True)
args=parser.parse_args()
print(json.dumps(dict(vcl=program(args.profile),get_headers={'X-WV-Gateway':'e'*64},purge_headers={'X-UltraCache-Token':'b'*64})))
