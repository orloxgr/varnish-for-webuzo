"""Static CMS cookie names for generated VCL; never used by visitor requests."""
import hashlib
import re
from cms_discovery import read_literal
import cms_metadata


def joomla_name(root):
    """Read the stock Joomla 3–6 site-session name without bootstrapping PHP."""
    try: version=read_literal(root,'libraries/src/Version.php')
    except FileNotFoundError: version=read_literal(root,'libraries/cms/version/version.php')
    major=re.search(r'\bconst\s+MAJOR_VERSION\s*=\s*([3-6])\s*;',version)
    release=re.search(r"\b(?:const\s+RELEASE|\$RELEASE)\s*=\s*['\"]([3-6])\.[0-9]+['\"]\s*;",version)
    if not (major or release):raise cms_metadata.MetadataUnavailable('Unsupported Joomla cookie naming')
    major=int(major[1] if major else release[1])
    text=read_literal(root,'configuration.php')
    tokens=[token for token in cms_metadata.TOKEN.findall(text) if not token.startswith(('//','/*','#'))]
    _,values,_=cms_metadata.settings(text)
    for name in ('secret','session_name'):
        occurrences=[i for i,t in enumerate(tokens[:-1]) if t=='$' and tokens[i+1]==name]
        if occurrences and (len(occurrences)!=1 or name not in values):
            raise cms_metadata.MetadataUnavailable('Dynamic cookie settings are not evaluated')
    if not values.get('secret'):raise cms_metadata.MetadataUnavailable('Joomla cookie secret is unavailable')
    seed=values.get('session_name','site' if major==3 else r'Joomla\CMS\Application\SiteApplication')
    first=hashlib.md5((values['secret']+seed).encode()).hexdigest()
    return hashlib.md5(first.encode()).hexdigest()
