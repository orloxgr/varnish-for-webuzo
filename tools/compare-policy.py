"""Explicit development check; never called by the plugin or installer."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--other',type=Path,required=True)
    parser.add_argument('--left-report',type=Path)
    parser.add_argument('--right-report',type=Path)
    args=parser.parse_args()
    if bool(args.left_report)!=bool(args.right_report):parser.error('Supply both parity reports together')
    root=Path(__file__).resolve().parents[1]
    digests={}
    for name in ('shared/native/cookie_handoff.c','shared/native/cookie_handoff.vcc','shared/native/delivery_continuation.c','shared/native_build.py',
                 'shared/native/delivery_envelope.c','shared/native/delivery_envelope.h',
                 'shared/cache-policy.vcl','shared/vcl/core.vcl','shared/vcl/cookies.vcl',
                 'shared/vcl/cookie-delivery.vcl','shared/vcl/http-cache.vcl',
                 'shared/vcl/aggressive.vcl','shared/vcl/cms-routes.vcl',
                 'shared/aggressive.py','shared/cms_routes.py','shared/cms_discovery.py','shared/cms_metadata.py','shared/cms_cookies.py',
                 'shared/vcl/representations.vcl','shared/vcl/ultracache-esi.vcl',
                 'shared/vcl_source.py','shared/VCL-ARCHITECTURE.md',
                 'shared/cookie_admin.py','shared/cookie_defaults.py','shared/cookie-defaults.json','shared/cookie_control.py','shared/cookie-assessments.json',
                 'shared/cookie-policies.json','shared/cookie_catalogue.py','shared/cookie_recognition.py',
                 'shared/CONTRACT.md','shared/ESI-DELIVERY-DRAFT.md','shared/COOKIE-CONTROL.md','shared/cookie-recognition/recognition.json',
                 'shared/cookie-recognition/Open-Cookie-Database-LICENSE.txt',
                 'tests/shared_policy_cases.json','tests/shared_policy_parity.py','tests/test_cookie_wire_contract.py',
                 'tests/test_delivery_continuation.py','tests/test_delivery_envelope.py','tools/build-cookie-assessments.py'):
        left=(root/name).read_bytes();right=(args.other/name).read_bytes()
        if left!=right:raise SystemExit('Different shared content: '+name)
        digests[name]=hashlib.sha256(left).hexdigest()
    result=dict(identical_files=digests)
    if args.left_report:
        left=json.loads(args.left_report.read_text(encoding='utf-8'))
        right=json.loads(args.right_report.read_text(encoding='utf-8'))
        if left!=right:raise SystemExit('Native parity reports differ')
        if any(left.get(field)!=digests[name] for field,name in (
            ('policy_sha256','shared/cache-policy.vcl'),('cases_sha256','tests/shared_policy_cases.json'),
            ('catalogue_sha256','shared/cookie-policies.json'),('compiler_sha256','shared/cookie_catalogue.py'),
            ('source_loader_sha256','shared/vcl_source.py'),('admin_module_sha256','shared/cookie_admin.py'),('defaults_sha256','shared/cookie-defaults.json'),
            ('defaults_module_sha256','shared/cookie_defaults.py'))):
            raise SystemExit('The reports do not test these source files')
        modules = {name.removeprefix('shared/'): value for name, value in digests.items()
                   if name == 'shared/cache-policy.vcl' or name.startswith('shared/vcl/')}
        if left.get('policy_modules') != modules:
            raise SystemExit('The reports do not test all current VCL source modules')
        handoff={name.removeprefix('shared/'):value for name,value in digests.items()
                 if name.startswith('shared/native/') or name=='shared/native_build.py'}
        if left.get('handoff_sources') != handoff:
            raise SystemExit('The reports do not test the current native cookie handoff')
        cms={name.removeprefix('shared/'):value for name,value in digests.items() if name in
             ('shared/aggressive.py','shared/cms_routes.py','shared/cms_discovery.py','shared/cms_metadata.py','shared/cms_cookies.py')}
        if left.get('cms_sources')!=cms:raise SystemExit('The reports do not test the current CMS policy sources')
        cases=json.loads((root/'tests/shared_policy_cases.json').read_text(encoding='utf-8'))
        expected=[dict(case=case['name'],profile=profile,result='passed') for profile in ('basic','ultracache')
            for case in cases if profile in case.get('profiles',['basic','ultracache'])]
        if left['results']!=expected:raise SystemExit('The reports do not cover the complete shared suite')
        result['matching_native_runs']=len(expected)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
