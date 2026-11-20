"""Journal native/app cookie changes through the shared authenticated transport."""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shared'))
import cookie_control
import cookie_execution
import cookie_defaults


def configuration(value, site):
    return cookie_control.integration(value, site['domain'], site['names'])


def snapshot(config, site):
    return cookie_control.materialized_snapshot(config.get('cookie_policies'), site.get('cookie_policies'),site.get('profile','basic'))


def operation(site, integration, policy, kind='apply'):
    client = cookie_control.Client(integration, site['domain'], site['token'], policy, aliases=site['names'])
    return dict(site=site['id'], configuration=copy.deepcopy(integration), host=site['domain'],
                aliases=list(site['names']), token=site['token'], policy=copy.deepcopy(policy),
                request_id=client.request_id, base_digest='', target_digest=client.target_digest, phase='new',kind=kind)


def plan(previous, following, force_sites=()):
    operations = []
    execution = cookie_execution.projections()
    for identity, site in sorted(following['sites'].items()):
        old = previous.get('sites', {}).get(identity)
        selected = configuration(site.get('cookie_integration'), site)
        before = configuration(old.get('cookie_integration'), old) if old else configuration(None, site)
        if before['enabled']:
            before,_=cookie_control.reconcile_integration(before,site['domain'],site['names'])
        switched = before['enabled'] and (not selected['enabled'] or before['url'] != selected['url'])
        if switched:
            # Disconnect explicitly restores the application's baseline first.
            operations.append(operation(old, before, cookie_control.snapshot(), 'disconnect'))
        if not selected['enabled']:
            continue
        changed=(cookie_defaults.changed(previous,following,site.get('profile','basic'),old.get('profile','basic') if old else None) or old is None or
                 execution(previous.get('cookie_policies'),old.get('cookie_policies'),old.get('profile','basic'))!=execution(following.get('cookie_policies'),site.get('cookie_policies'),site.get('profile','basic')))
        if identity in force_sites or not before['enabled'] or switched or changed:
            operations.append(operation(site, selected, snapshot(following, site)))
    return operations


def client_for(item):
    client = cookie_control.Client(item['configuration'], item['host'], item['token'], item['policy'],
                                   request_id=item['request_id'], aliases=item['aliases'])
    client.base_digest = item['base_digest']
    if client.target_digest != item['target_digest']:
        raise ValueError('Cookie transaction snapshot does not match its journal')
    return client


def prepare_item(item, journal, persist):
    client = client_for(item)
    result = client.call('status')
    if not isinstance(result.get('capabilities'),dict) or result['capabilities'].get('scopedCookiePolicies') is not True:
        raise cookie_control.ControlError('WordPress does not support scoped cookie policies')
    item.update(base_digest=client.base_digest, phase='preparing')
    persist(journal)  # Recovery must know the identity before remote staging.
    client.call('prepare')
    item['phase'] = 'prepared'; persist(journal)


def prepare(journal, persist):
    disconnected=set()
    for item in journal.get('cookie_operations', []):
        if item.get('kind','apply')=='apply' and item['site'] in disconnected:
            # HTTP/HTTPS or aliases can reach the same WordPress installation.
            # Inspect the new endpoint only after its old snapshot is cleared.
            item['phase']='deferred';persist(journal)
            continue
        prepare_item(item,journal,persist)
        if item.get('kind')=='disconnect':disconnected.add(item['site'])


def commit(journal, persist):
    for item in journal.get('cookie_operations', []):
        if item['phase']=='deferred':prepare_item(item,journal,persist)
        item['phase'] = 'committing'; persist(journal)
        client_for(item).call('commit')
        item['phase'] = 'committed'; persist(journal)


def rollback(journal, persist):
    for item in reversed(journal.get('cookie_operations', [])):
        if item['phase'] in ('new', 'deferred', 'rolled-back'):
            continue
        # A prepare/commit may have succeeded even if its response was lost.
        # Always use the journaled request/base/target, never a new transaction.
        result=client_for(item).call('rollback')
        item['rollback_state']=result['rollbackState']
        item['rollback_active_digest']=result['activeDigest']
        item['phase'] = 'rolled-back'; persist(journal)


def preserved_newer(journal):
    return [dict(site=item['site'],state=item['rollback_state'],active_digest=item['rollback_active_digest'])
            for item in journal.get('cookie_operations',[]) if item.get('rollback_state') in ('not-applied','superseded')
            and item.get('rollback_active_digest')!=item.get('base_digest')]


def status(site, selected, config):
    value = configuration(selected, site)
    client = cookie_control.Client(value, site['domain'], site['token'], snapshot(config, site), aliases=site['names'])
    result = client.call('status')
    return {key: result[key] for key in ('activeDigest','capabilities','stage') if key in result}
