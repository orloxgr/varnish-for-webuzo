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
    for name in ('shared/cache-policy.vcl','shared/cookie-policies.json','shared/cookie_catalogue.py','shared/cookie_delivery.py',
                 'shared/CONTRACT.md','shared/cookie-recognition/recognition.json',
                 'shared/cookie-recognition/Open-Cookie-Database-LICENSE.txt',
                 'tests/shared_policy_cases.json','tests/shared_policy_parity.py'):
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
            ('delivery_module_sha256','shared/cookie_delivery.py'))):
            raise SystemExit('The reports do not test these source files')
        cases=json.loads((root/'tests/shared_policy_cases.json').read_text(encoding='utf-8'))
        expected=[dict(case=case['name'],profile=profile,result='passed') for profile in ('basic','ultracache')
            for case in cases if profile in case.get('profiles',['basic','ultracache'])]
        if left['results']!=expected:raise SystemExit('The reports do not cover the complete shared suite')
        result['matching_native_runs']=len(expected)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
