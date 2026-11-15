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
    results=[]
    for profile in ('basic','ultracache'):
        rendered=json.loads(subprocess.run([sys.executable,str(args.adapter),'--profile',profile],capture_output=True,text=True,check=True).stdout)
        for case in json.loads(cases.read_text(encoding='utf-8')):
            if profile not in case.get('profiles',['basic','ultracache']):continue
            if args.case and not any(value.lower() in case['name'].lower() for value in args.case):continue
            server='\n'.join(case['origin']).removeprefix('accept\n')
            client='\n'.join(case['requests'])
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
    report=dict(policy_sha256=hashlib.sha256(policy.read_bytes()).hexdigest(),cases_sha256=hashlib.sha256(cases.read_bytes()).hexdigest(),results=results)
    encoded=json.dumps(report,indent=2)+'\n'
    if args.output:args.output.write_text(encoded,encoding='utf-8')
    print(encoded,end='')


if __name__=='__main__':main()
