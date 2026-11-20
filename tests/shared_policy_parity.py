"""Run identical HTTP assertions against a panel's generated native VCL."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--adapter',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--case',action='append',default=[])
    args=parser.parse_args()
    cases=Path(__file__).with_name('shared_policy_cases.json')
    policy=Path(__file__).resolve().parents[1]/'shared/cache-policy.vcl'
    sys.path.insert(0,str(policy.parent))
    from vcl_source import manifest
    catalogue_version=json.loads(policy.with_name('cookie-policies.json').read_text(encoding='utf-8'))['version']
    results=[]
    for profile in ('basic','ultracache'):
        programs={}
        for case in json.loads(cases.read_text(encoding='utf-8')):
            if profile not in case.get('profiles',['basic','ultracache']):continue
            if args.case and not any(value.lower() in case['name'].lower() for value in args.case):continue
            configuration=json.dumps({key:case.get(key) for key in ('legacy_cookie_delivery','site_settings')},sort_keys=True)
            if configuration not in programs:
                command=[sys.executable,str(args.adapter),'--profile',profile]
                if 'legacy_cookie_delivery' in case:command.extend(['--legacy-cookie-delivery',json.dumps(case['legacy_cookie_delivery'])])
                if 'site_settings' in case:command.extend(['--site-settings',json.dumps(case['site_settings'])])
                programs[configuration]=json.loads(subprocess.run(command,capture_output=True,text=True,check=True).stdout)
            rendered=programs[configuration]
            server='\n'.join(case['origin']).removeprefix('accept\n')
            client='\n'.join(case['requests'])
            server=server.replace('@@CATALOGUE_VERSION@@',catalogue_version)
            client=client.replace('@@CATALOGUE_VERSION@@',catalogue_version)
            for marker,headers in (('@@GET_HEADERS@@',rendered.get('get_headers',{})),('@@PURGE_HEADERS@@',rendered.get('purge_headers',{}))):
                client=client.replace(marker,' '.join('-hdr '+json.dumps(k+': '+v) for k,v in headers.items()))
            content=('varnishtest '+json.dumps(case['name']+' '+profile)+'\nserver s1 {\n'+server+'\n} -start\n'
                +'varnish v1 '+case.get('varnish_args','')+' -arg "-p uncacheable_ttl=37 -p default_grace=41 -p default_keep=23" -vcl {\n'+rendered['vcl']+'\n} -start\n'
                +'client c1 {\n'+client+'\n} -run\nserver s1 -wait\n'+case.get('tail','')+'\n')
            with tempfile.TemporaryDirectory(prefix='shared-policy-parity-') as folder:
                script=Path(folder)/'case.vtc';script.write_text(content,encoding='utf-8')
                run=subprocess.run(['varnishtest','-t','20',str(script)],capture_output=True,text=True,timeout=30)
            if run.returncode:
                print(case['name']+' '+profile+' FAILED\n'+run.stdout+run.stderr,file=sys.stderr)
                raise SystemExit(1)
            results.append(dict(case=case['name'],profile=profile,result='passed'))
    report=dict(policy_sha256=hashlib.sha256(policy.read_bytes()).hexdigest(),
        handoff_sources={name:hashlib.sha256((policy.parent/name).read_bytes()).hexdigest()
                         for name in ('native/cookie_handoff.c','native/cookie_handoff.vcc','native/delivery_continuation.c',
                                      'native/delivery_envelope.c','native/delivery_envelope.h','native_build.py')},
        policy_modules=manifest(),
        source_loader_sha256=hashlib.sha256(policy.with_name('vcl_source.py').read_bytes()).hexdigest(),
        defaults_sha256=hashlib.sha256(policy.with_name('cookie-defaults.json').read_bytes()).hexdigest(),
        defaults_module_sha256=hashlib.sha256(policy.with_name('cookie_defaults.py').read_bytes()).hexdigest(),
        admin_module_sha256=hashlib.sha256(policy.with_name('cookie_admin.py').read_bytes()).hexdigest(),
        catalogue_sha256=hashlib.sha256(policy.with_name('cookie-policies.json').read_bytes()).hexdigest(),
        compiler_sha256=hashlib.sha256(policy.with_name('cookie_catalogue.py').read_bytes()).hexdigest(),
        cms_sources={name:hashlib.sha256(policy.with_name(name).read_bytes()).hexdigest() for name in ('aggressive.py','cms_routes.py','cms_discovery.py','cms_metadata.py','cms_cookies.py')},
        cases_sha256=hashlib.sha256(cases.read_bytes()).hexdigest(),results=results)
    encoded=json.dumps(report,indent=2)+'\n'
    if args.output:args.output.write_text(encoded,encoding='utf-8')
    print(encoded,end='')


if __name__=='__main__':main()
