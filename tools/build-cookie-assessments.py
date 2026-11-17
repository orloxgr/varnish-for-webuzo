"""Per-record, explicitly inferred assessments from the pinned source CSV.

This is a reproducible editorial aid, not executable policy. Category labels do
not participate in the inference. Only existing reviewed policies remain active
by default; every other suggestion requires an explicit user choice.
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='Pinned upstream open-cookie-database.csv')
    parser.add_argument('--revision', required=True, help='Upstream commit containing this source CSV')
    parser.add_argument('--version', default='2026.11.17.1', help='Editorial assessment version')
    parser.add_argument('--output', type=Path, required=True, help='Editorial assessment JSON to write; never activated automatically')
    args = parser.parse_args()
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
        text = description.lower()
        entry = dict(name=name, provider=source['Platform'], domain=source['Domain'], description=description,
                     proposal='automatic', htmlEffect='unknown', confidence='inferred-low',
                     reason='The description does not establish whether the hosting application uses this value to render HTML. Existing policy is retained.',
                     sources=[source_url], method='description-and-name-inference; not independently verified')
        reviewed = _proposal(match, catalogue)
        if reviewed:
            entry.update(reviewed)
            entry['method'] = 'existing-reviewed-execution-policy'
            entry['sources'] = list(dict.fromkeys([source_url, *entry['sources']]))
        elif re.search(r'authenticat|logged[ -]in|log[ -]?in credentials|password|csrf|xsrf|shopping cart|basket|payment session|customer session', text):
            entry.update(proposal='private', htmlEffect='possible-private',
                         reason='Description refers to authentication, account security or a personal cart/session. Private handling is suggested; no new bypass is activated automatically. Confirm application and cookie scope.')
        elif re.search(r'consent|cookie preference|cookie polic|cookie banner|cookies.*accept|accept.*cookies', text):
            entry.update(htmlEffect='consent-dependent',
                         reason='Consent may alter server output, client scripts or both. Keep the existing application/CMP authority; the description alone does not authorize sharing or cookie issuance.')
        elif re.search(r'currency|preferred language|language preference|selected language|language setting|preferred country|country selection|timezone|time zone', text):
            entry.update(proposal='variant', htmlEffect='possible-public-variant',
                         reason='Description identifies a language, currency or regional preference that may select public HTML. An explicit public variant is suggested if the application renders it server-side; it is not activated from metadata.')
        elif re.search(r'personali[sz]|recommendation|recently viewed|wishlist|wish list|a/b test|ab test|split.test|experiment|test variant', text):
            entry.update(htmlEffect='application-dependent',
                         reason='Description mentions personalization, experiment assignment or browsing history. It may affect server HTML, a private fragment or only client JavaScript; retain existing handling until the site-specific path is known.')
        elif re.search(r'session identif|session id|session token|server affinity|load balanc|sticky session|session state', text):
            entry.update(htmlEffect='session-dependent',
                         reason='A session/affinity role is described, but its contents and effect on public HTML are not established. Retain the existing policy; do not infer shared cache merely from a Functional/Analytics label.')
        elif re.search(r'statistic|analytics|analytical|track.*(visitor|user|page|click|conversion)|measure.*(visitor|audience|campaign)|visitor.*(count|statistic)|advertising campaign|ad campaign|conversion tracking|marketing campaign', text):
            entry.update(proposal='shared', htmlEffect='probably-none-in-initial-html',
                         reason='The supplied description describes measurement/attribution rather than selecting initial server HTML. Shared variation is an inference requiring a local choice; cookie values, provider delivery and consent remain intact.')
        if source['Domain'] and not reviewed:
            entry['reason'] += ' The listed provider domain may make this a third-party cookie absent from requests to the hosted site; name alone does not prove first-party applicability.'
        if source['Data Controller']:
            entry['dataController'] = source['Data Controller']
        assert source['ID'] not in records
        records[source['ID']] = entry

    result = dict(schemaVersion=1, version=args.version, sourceRevision=revision,
                  sourceLicense='Apache-2.0', sourceLicenseFile='cookie-recognition/Open-Cookie-Database-LICENSE.txt',
                  sourceSha256=hashlib.sha256(raw).hexdigest(),
                  method='Every source record evaluated individually by explicit description/name cues. Inferences are not verified execution policies; categories are not inputs. No visitor values or runtime network lookup.',
                  records=records)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({'assessed': len(records), 'confidence': dict(collections.Counter(row['confidence'] for row in records.values())),
                      'suggestions': dict(collections.Counter(row['proposal'] for row in records.values()))}))



if __name__ == '__main__':
    main()
