"""Credential files are created/removed with the hosting UID, never as root."""
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

def main():
    if os.geteuid()==0 or len(sys.argv)!=4 or sys.argv[1] not in ('save','remove') or not re.fullmatch('[0-9a-f]{32}',sys.argv[3]):raise ValueError('Invalid account credential operation')
    operation,home,sid=sys.argv[1:]
    parent=os.open(home,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    folder='.varnish-for-webuzo';directory=None;temporary=None
    try:
        if os.fstat(parent).st_uid!=os.geteuid():raise ValueError('Account home ownership mismatch')
        if operation=='save':
            try:os.mkdir(folder,0o700,dir_fd=parent)
            except FileExistsError:pass
        try:directory=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        except FileNotFoundError:
            if operation=='remove':return
            raise
        info=os.fstat(directory)
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('Unsafe account credential directory')
        if operation=='remove':
            try:os.unlink(sid+'.json',dir_fd=directory)
            except FileNotFoundError:pass
            return
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError('Credential payload too large')
        value=json.loads(raw)
        if (not isinstance(value,dict) or set(value)!={'site','names','token','roots'} or value['site']!=sid or
            not isinstance(value['token'],str) or not re.fullmatch('[0-9a-f]{64}',value['token']) or
            not isinstance(value['names'],list) or any(not isinstance(n,str) or not re.fullmatch('[a-z0-9.-]+',n) for n in value['names'])):raise ValueError('Invalid site credential')
        if not isinstance(value['roots'],list) or not value['roots']:raise ValueError('Missing native document roots')
        private=(Path(home)/folder).resolve()
        for root in value['roots']:
            if not isinstance(root,str) or not Path(root).is_absolute() or private.is_relative_to(Path(root).resolve()):
                raise ValueError('The private credential directory must be outside every document root')
        raw=json.dumps({key:value[key] for key in ('site','names','token')}).encode()
        temporary='.tmp-'+secrets.token_hex(16)
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,sid+'.json',src_dir_fd=directory,dst_dir_fd=directory);temporary=None;os.fsync(directory)
    finally:
        if directory is not None:
            if temporary is not None:os.unlink(temporary,dir_fd=directory)
            os.close(directory)
        os.close(parent)

if __name__=='__main__':
    try:main();print('{"ok":true}')
    except Exception as error:print(json.dumps(dict(ok=False,error=str(error))));raise SystemExit(1)
