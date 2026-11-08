"""Package only public source files, with reproducible ZIP metadata."""
from datetime import datetime,timezone
import hashlib
import json
import os
import re
from pathlib import Path
import zipfile
ROOT=Path(__file__).resolve().parents[1]
def package_version():
    version=json.loads((ROOT/'info.json').read_text(encoding='utf-8'))['version']
    header=(ROOT/'varnish-for-webuzo.php').read_text(encoding='utf-8').split('*/',1)[0]
    found=re.search(r'^[ \t]*Version:[ \t]*([^\r\n]+)',header,re.M)
    if not isinstance(version,str) or not version or found is None or found[1].strip()!=version:
        raise ValueError('The PHP plugin Version header must match info.json before packaging')
    return version

def build():
    version=package_version()
    paths=[ROOT/name for name in ('varnish-for-webuzo.php','info.json','LICENSE','UPSTREAM','README.md')]
    for folder in ('src','templates','profiles','panel','docs'):
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
    connector_version=re.search(r'^\s*\*?\s*Version:\s*(\S+)',(ROOT/'wordpress/varnish-cache-for-webuzo.php').read_text(),re.M)[1]
    connector=target.parent/('varnish-cache-for-webuzo-wordpress-'+connector_version+'.zip')
    # An unchanged connector is a separate package, with its own version/date.
    connector_sources=(ROOT/'wordpress/varnish-cache-for-webuzo.php',ROOT/'LICENSE',ROOT/'wordpress/readme.txt')
    connector_stamp=datetime.fromtimestamp(int(os.environ.get('SOURCE_DATE_EPOCH',max(p.stat().st_mtime for p in connector_sources))),timezone.utc).timetuple()[:6]
    connector_files={'varnish-cache-for-webuzo/'+name:source.read_bytes() for source,name in ((ROOT/'wordpress/varnish-cache-for-webuzo.php','varnish-cache-for-webuzo.php'),(ROOT/'LICENSE','LICENSE'),(ROOT/'wordpress/readme.txt','readme.txt'))}
    unchanged=False
    if connector.exists():
        with zipfile.ZipFile(connector) as archive:
            unchanged=len(archive.infolist())==len(connector_files) and set(archive.namelist())==set(connector_files) and all(archive.read(name)==data for name,data in connector_files.items())
    if not unchanged:
        with zipfile.ZipFile(connector,'w',zipfile.ZIP_DEFLATED) as archive:
            for name,data in connector_files.items():
                item=zipfile.ZipInfo(name,connector_stamp);item.external_attr=0o100644<<16;item.compress_type=zipfile.ZIP_DEFLATED
                archive.writestr(item,data)
    digest=hashlib.sha256(connector.read_bytes()).hexdigest()
    with (target.parent/'SHA256SUMS').open('a') as output:output.write(digest+'  '+connector.name+'\n')
    print(connector.name,digest)
    return target
if __name__=='__main__':build()
