"""Package only public source files, with reproducible ZIP metadata."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import zipfile
ROOT=Path(__file__).resolve().parents[1]
def build():
    version=json.loads((ROOT/'info.json').read_text())['version']
    paths=[ROOT/name for name in ('varnish-for-webuzo.php','info.json','LICENSE','UPSTREAM','README.md')]
    for folder in ('src','templates','panel','docs'):
        paths.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix not in ('.pyc','.zip'))
    epoch=int(os.environ.get('SOURCE_DATE_EPOCH',max(p.stat().st_mtime for p in paths)))
    stamp=datetime.fromtimestamp(epoch,timezone.utc).timetuple()[:6]
    target=ROOT/'dist'/('varnish-for-webuzo-'+version+'.zip');target.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(paths):
            if path.is_symlink():raise ValueError('Source links cannot be distributed')
            item=zipfile.ZipInfo('varnish-for-webuzo/'+path.relative_to(ROOT).as_posix(),stamp)
            item.external_attr=0o100644<<16;item.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(item,path.read_bytes())
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    (target.parent/'SHA256SUMS').write_text(digest+'  '+target.name+'\n')
    print(target.name,digest)
    connector=target.parent/('varnish-cache-for-webuzo-wordpress-'+version+'.zip')
    with zipfile.ZipFile(connector,'w',zipfile.ZIP_DEFLATED) as archive:
        for source,name in ((ROOT/'wordpress/varnish-cache-for-webuzo.php','varnish-cache-for-webuzo.php'),(ROOT/'LICENSE','LICENSE'),(ROOT/'wordpress/readme.txt','readme.txt')):
            item=zipfile.ZipInfo('varnish-cache-for-webuzo/'+name,stamp);item.external_attr=0o100644<<16;item.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(item,source.read_bytes())
    digest=hashlib.sha256(connector.read_bytes()).hexdigest()
    with (target.parent/'SHA256SUMS').open('a') as output:output.write(digest+'  '+connector.name+'\n')
    print(connector.name,digest)
    return target
if __name__=='__main__':build()
