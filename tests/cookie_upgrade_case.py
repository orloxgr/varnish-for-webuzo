"""Persisted .9 execution metadata and manual choices for real adapter apply tests.

No old runtime code is substituted: only the metadata a .9 installation saved.
The maintained adapter tests run the current normal apply with owned fake I/O.
"""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'shared'))
import cookie_admin as admin

VARIANTS=('default','shared','variant','private','reset')


def previous_metadata():
    return json.loads((ROOT/'tests/fixtures/cookie-defaults-2026.11.20.9.json').read_text(encoding='utf-8'))['saved']


def central_choices():
    return admin.normalize(dict(schemaVersion=2,rules=[dict(id='custom:central-'+action,
        match=dict(kind='exact',value='central_'+action),description='Saved central choice',
        actions=dict(basic=action,ultracache=action)) for action in ('shared','variant','private')]))


def site_choices(profile,choice):
    if choice=='default':return None
    actions={p:(None if p==profile else 'variant') if choice=='reset' else choice for p in ('basic','ultracache')}
    return admin.normalize(dict(schemaVersion=2,rules=[dict(id='custom:cart-hash',
        match=dict(kind='exact',value='woocommerce_cart_hash'),description='Saved site choice',actions=actions)]))


def expected_action(profile,choice):
    return ('private' if profile=='basic' else 'shared') if choice in ('default','reset') else choice
