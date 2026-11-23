"""Per-record, explicitly inferred assessments from the pinned source CSV.

Concrete editorial defaults are executable. Category labels do not participate
in the inference. Every record has an action; confidence describes the evidence,
not whether its policy runs. New recognition downloads remain metadata.
"""
import argparse
import collections
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / 'shared'
sys.path.insert(0, str(SHARED))
from cookie_admin import _proposal, _recognition_match
from cookie_catalogue import load_catalogue
from cookie_defaults import infer, bundle


def write_defaults():
    """Rebuild ordinary defaults from pinned assessments + reviewed catalogue."""
    bundle.cache_clear()
    policy, metadata = bundle()
    artifact = dict(policy, version=metadata['version'], sourceRevision=metadata['sourceRevision'])
    (SHARED / 'cookie-defaults.json').write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='Pinned upstream open-cookie-database.csv')
    parser.add_argument('--revision', help='Upstream commit containing this source CSV')
    parser.add_argument('--version', default='2026.11.20.5', help='Editorial assessment version')
    parser.add_argument('--output', type=Path, help='Versioned concrete editorial default JSON')
    parser.add_argument('--defaults-only', action='store_true', help='Regenerate defaults from existing pinned assessments and reviewed catalogue, without CSV changes')
    args = parser.parse_args()
    if args.defaults_only:
        if args.source or args.revision or args.output:
            parser.error('--defaults-only does not import a source or write assessments')
        artifact = write_defaults()
        print(json.dumps({'defaults':len(artifact['rules']),'version':artifact['version'],'sourceRevision':artifact['sourceRevision']}))
        return
    if not args.source or not args.revision or not args.output:
        parser.error('--source, --revision and --output are required for CSV assessment generation')
    raw = args.source.read_bytes()
    catalogue = load_catalogue()
    revision = args.revision
    if not re.fullmatch('[0-9a-f]{40}', revision):
        parser.error('--revision must identify the full upstream Git commit')
    source_url = 'https://github.com/jkwakman/Open-Cookie-Database/blob/' + revision + '/open-cookie-database.csv'
    records = {}
    for source in csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline='')):
        name, description = source['Cookie / Data Key name'], source['Description'].strip()
        row = {'name': name, 'wildcard': source['Wildcard match'] == '1'}
        match = _recognition_match(row)
        reviewed = _proposal(match, catalogue)
        entry = dict(name=name, provider=source['Platform'], domain=source['Domain'], description=description,
                     wildcard=source['Wildcard match'] == '1',
                     **infer(name, source['Platform'], description, reviewed))
        entry['sources'] = list(dict.fromkeys([source_url, *entry['sources']]))
        entry['matchValue'] = name.strip()
        if name != entry['matchValue']:
            entry['reason'] += ' Editorial correction: surrounding whitespace in the source cookie name is not part of the literal match.'
        basic=entry.pop('proposal')
        reviewed_uc=_proposal(match,catalogue,'ultracache')
        entry['actions']={'basic':basic,'ultracache':reviewed_uc['proposal'] if reviewed_uc else basic}
        if source['Data Controller']:
            entry['dataController'] = source['Data Controller']
        assert source['ID'] not in records
        records[source['ID']] = entry

    groups = collections.defaultdict(list)
    for row in records.values():
        groups[(row['name'], row['wildcard'])].append(row)
    for group in groups.values():
        for profile in ('basic','ultracache'):
            if len({row['actions'][profile] for row in group}) > 1:
                action=max((row['actions'][profile] for row in group),key={'shared':0,'variant':1,'private':2}.get)
                for row in group:row['actions'][profile]=action

    result = dict(schemaVersion=2, version=args.version, sourceRevision=revision,
                  sourceLicense='Apache-2.0', sourceLicenseFile='cookie-recognition/Open-Cookie-Database-LICENSE.txt',
                  sourceSha256=hashlib.sha256(raw).hexdigest(),
                  method='Concrete per-record editorial decisions based on literal names and descriptions. Inference is not site-specific verification. Categories are not inputs. No visitor values or runtime lookup.',
                  records=records)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    if args.output.resolve() == (SHARED / 'cookie-assessments.json').resolve():
        write_defaults()
    print(json.dumps({'assessed': len(records), 'confidence': dict(collections.Counter(row['confidence'] for row in records.values())),
                      'suggestions': {p:dict(collections.Counter(row['actions'][p] for row in records.values())) for p in ('basic','ultracache')}}))



if __name__ == '__main__':
    main()
