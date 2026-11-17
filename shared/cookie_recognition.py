"""Update recognition metadata from upstream; never generates cache/consent rules.

The panel adapter supplies its private persistent directory and bundled snapshot.
Only fixed upstream HTTPS URLs are fetched. HTTP requests never call this module.
"""
from contextlib import contextmanager
import csv
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import urllib.error
import urllib.request

SOURCE = 'https://github.com/jkwakman/Open-Cookie-Database'
HEAD = 'https://api.github.com/repos/jkwakman/Open-Cookie-Database/commits/master'
RAW = 'https://raw.githubusercontent.com/jkwakman/Open-Cookie-Database/'
FIELDS = ('ID', 'Platform', 'Category', 'Cookie / Data Key name', 'Domain', 'Retention period', 'Wildcard match')
# Bounds apply only to untrusted upstream input, never to cache work or requests.
MAX_CSV_BYTES = 32 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_RECORDS = 100000
MAX_FIELD_CHARACTERS = 256 * 1024
MAX_COLUMNS = 128
CONTROLS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


def _check_columns(text):
    """Bound CSV row allocation before DictReader constructs any field arrays.

    Match the default dialect's quote/escaped-quote handling, including quoted
    newlines and literal quotes inside unquoted fields. Quoted commas are data.
    """
    columns, field_start, quoted, after_quote = 1, True, False, False
    for char in text:
        if quoted:
            if char == '"':
                quoted, after_quote = False, True
            continue
        if after_quote:
            after_quote = False
            if char == '"':
                quoted = True
                continue
            if char not in ',\r\n':
                raise csv.Error('Unexpected character after quoted CSV field')
        if char == ',':
            columns += 1
            if columns > MAX_COLUMNS:
                raise ValueError('Upstream CSV exceeds the 128-column input safety limit')
            field_start = True
        elif char in '\r\n':
            columns, field_start = 1, True
        else:
            if field_start and char == '"':
                quoted = True
            field_start = False


def parse_csv(data):
    if len(data) > MAX_CSV_BYTES:
        raise ValueError('Upstream CSV exceeds the 32 MiB input safety limit')
    csv.field_size_limit(MAX_FIELD_CHARACTERS)
    text = data.decode('utf-8-sig')
    if CONTROLS.search(text):
        raise ValueError('Unexpected control character in upstream CSV')
    _check_columns(text)
    reader = csv.DictReader(io.StringIO(text, newline=''), strict=True)
    if (not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames) or
            not set(FIELDS).issubset(reader.fieldnames)):
        raise ValueError('Upstream CSV columns changed')
    cookies = []
    for row in reader:
        if None in row or any(row.get(key) is None for key in FIELDS):
            raise ValueError('Incomplete upstream CSV row')
        if not row['ID'] or not row['Cookie / Data Key name'] or row['Wildcard match'] not in ('0', '1'):
            raise ValueError('Invalid upstream recognition entry')
        if len(cookies) >= MAX_RECORDS:
            raise ValueError('Upstream CSV exceeds the 100,000-record input safety limit')
        cookies.append(dict(id=row['ID'], name=row['Cookie / Data Key name'], provider=row['Platform'],
                            category=row['Category'], domain=row['Domain'], retention=row['Retention period'],
                            description=row.get('Description', ''),
                            wildcard=row['Wildcard match'] == '1'))
    if not cookies:
        raise ValueError('Upstream database is empty')
    return cookies


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise ValueError('Upstream HTTP redirect refused')


def fetch(url):
    if url != HEAD and not re.fullmatch(re.escape(RAW) + r'[0-9a-f]{40}/(?:LICENSE|open-cookie-database\.csv)', url):
        raise ValueError('Unexpected upstream URL')
    request = urllib.request.Request(url, headers={'User-Agent': 'Varnish-Cookie-Recognition/1',
                                                  'Accept': 'application/vnd.github+json' if url == HEAD else '*/*'})
    maximum = MAX_CSV_BYTES if url.endswith('/open-cookie-database.csv') else MAX_METADATA_BYTES
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        if response.geturl() != url:
            raise ValueError('Unexpected upstream response URL')
        data = bytearray()
        while True:
            chunk = response.read(min(65536, maximum + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > maximum:
                raise ValueError('Upstream response exceeds its input safety limit')


def _safe_file(path):
    if path.is_symlink():
        raise ValueError('Unexpected recognition state symlink')
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Recognition state must be a root-private regular file')


def _directory(directory, create=False):
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or directory.resolve() != directory:
        raise ValueError('Unexpected recognition state directory')
    if create:
        directory.mkdir(mode=0o700, parents=False, exist_ok=True)
    if directory.exists():
        info = directory.stat()
        if not directory.is_dir() or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Recognition state directory must be root-private')
    return directory


@contextmanager
def _locked(directory):
    import fcntl
    directory = _directory(directory, create=True)
    path = directory / 'recognition.lock'
    _safe_file(path)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('Unexpected recognition lock ownership')
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield directory


def _read(directory):
    directory = _directory(directory)
    path = directory / 'recognition-state.json'
    _safe_file(path)
    if not path.exists():
        return {'schema': 1, 'automatic': True, 'database': None, 'status': {}}
    record = json.loads(path.read_text(encoding='utf-8'))
    if record.get('schema') != 1 or type(record.get('automatic')) is not bool or not isinstance(record.get('status'), dict):
        raise ValueError('Unsupported recognition state')
    return record


def _write(directory, record):
    path = directory / 'recognition-state.json'
    _safe_file(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.recognition-', dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            json.dump(record, handle, ensure_ascii=False, separators=(',', ':'))
            handle.write('\n'); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _database(record, bundled):
    return record['database'] or json.loads(Path(bundled).read_text(encoding='utf-8'))


def _status(record, bundled):
    data = _database(record, bundled)
    result = dict(automatic=record['automatic'], source='Open Cookie Database', source_url=SOURCE,
                license='Apache-2.0', revision=data.get('revision', ''), sha256=data.get('sha256', ''),
                records=len(data['records']), bundled=record['database'] is None,
                last_check=None, last_success=None, updated_at=None, result='bundled', error=None)
    result.update(record['status'])
    return result


def status(directory, bundled):
    return _status(_read(directory), bundled)


def database(directory, bundled):
    """Read recognition data locally. Its categories are descriptive, not policy."""
    return _database(_read(directory), bundled)


def configure(directory, bundled, automatic):
    if type(automatic) is not bool:
        raise ValueError('Automatic database updates must be a boolean')
    with _locked(directory) as directory:
        record = _read(directory)
        record['automatic'] = automatic
        _write(directory, record)
        return _status(record, bundled)


def update(directory, bundled, force=False):
    with _locked(directory) as directory:
        record = _read(directory)
        if not force and not record['automatic']:
            return _status(record, bundled)
        checked = datetime.datetime.now(datetime.timezone.utc).isoformat()
        stage = 'read upstream revision'
        try:
            revision = json.loads(fetch(HEAD)).get('sha')
            if not isinstance(revision, str) or not re.fullmatch('[0-9a-f]{40}', revision):
                raise ValueError('Upstream returned an invalid revision')
            current = _database(record, bundled)
            if record['database'] is not None and current.get('revision') == revision:
                result = 'unchanged'
            else:
                stage = 'check upstream license'
                license_data = fetch(RAW + revision + '/LICENSE')
                text = license_data.decode('utf-8-sig')
                if 'Apache License' not in text or 'Version 2.0, January 2004' not in text:
                    raise ValueError('Upstream license changed; retaining current database')
                stage = 'download recognition CSV'
                raw = fetch(RAW + revision + '/open-cookie-database.csv')
                stage = 'validate recognition CSV'
                cookies = parse_csv(raw)
                record['database'] = dict(schema=1, source='Open Cookie Database', repository=SOURCE,
                    revision=revision, license='Apache-2.0', license_text=text,
                    executable=False, sha256=hashlib.sha256(raw).hexdigest(), records=cookies)
                record['status']['updated_at'] = checked
                result = 'updated'
            record['status'].update(last_check=checked, last_success=checked, result=result, error=None)
        except (OSError, ValueError, TypeError, AttributeError, csv.Error) as error:
            if isinstance(error, urllib.error.HTTPError):
                detail = 'HTTP ' + str(error.code)
            elif isinstance(error, (ValueError, csv.Error)):
                detail = str(error) if not isinstance(error, json.JSONDecodeError) else 'Invalid upstream JSON'
            else:
                detail = type(error).__name__
            record['status'].update(last_check=checked, result='error', error=stage + ': ' + detail)
        _write(directory, record)
        return _status(record, bundled)
