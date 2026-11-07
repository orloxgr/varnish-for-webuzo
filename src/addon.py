"""One-shot root worker, reachable only through native panel-owned IPC files."""
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import engine
import transport

if __name__=='__main__':
    try:
        if os.geteuid()!=0 or len(sys.argv)!=3 or sys.argv[1]!='--request':raise ValueError('Invalid native request')
        identity=sys.argv[2]
        result=dict(ok=True,**engine.action(transport.request(identity)))
    except Exception as error:result=dict(ok=False,error=str(error))
    payload=json.dumps(result,ensure_ascii=True).encode()
    if len(payload)>32000 and len(sys.argv)==3:
        transport.publish(sys.argv[2],payload);print(json.dumps(dict(response=sys.argv[2])))
    else:print(payload.decode())
