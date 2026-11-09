"""Apply routing and policy as one recoverable change under a root-private lock."""
import copy
import json
from pathlib import Path
import secrets
import native
import policy
import routing
import service
import state
import credentials
import cache_size
import fragments
import profiles
import timeouts
import connections

SETTINGS=state.ROOT/'settings.json'
JOURNAL=state.ROOT/'transaction.json'

def settings():return state.read(SETTINGS,{})

def inventory(config):
    sites=native.collect()
    for sid,site in sites.items():
        previous=config.get('sites',{}).get(sid,{})
        site.update(enabled=bool(previous.get('enabled')) and not bool(site['error']),token=previous.get('token') or secrets.token_hex(32),ttl=previous.get('ttl',300),bypass=previous.get('bypass',[]))
        site.update(recv_vcl=previous.get('recv_vcl',''),backend_vcl=previous.get('backend_vcl',''))
        site['profile']=profiles.name(previous.get('profile','basic' if sid in config.get('sites',{}) else profiles.default(config)))
    return sites

def status():
    config=settings();sites=inventory(config)
    return dict(installed=bool(config.get('installed')),package=service.installed(),running=service.running(),memory_mb=config.get('memory_mb',256),
                default_profile=profiles.default(config),profiles=profiles.catalog(config),proxy_timeouts=timeouts.settings(config) if 'proxy_timeouts' in config else None,control_port=config.get('control_port'),
                sites=[{k:v for k,v in s.items() if k not in ('token','uid','gid','home','custom_domains','credential_roots')} for s in sites.values()])

def own_file(path,value,mode=0o600):
    raw=native.read(path).decode() if path.exists() or path.is_symlink() else None
    return dict(path=str(path),before=raw,after=value,mode=mode)

def plans(previous,next_config):
    changes=[];manifest={};desired={}
    if next_config.get('installed'):
        changes.append(own_file(routing.CONFIG/'origins.conf',routing.origins(next_config['origin'],timeouts.settings(next_config))+connections.render(next_config)))
        changes.append(own_file(routing.CONFIG/'client-ip.conf','<IfModule remoteip_module>\nRemoteIPHeader X-Forwarded-For\nRemoteIPInternalProxy 127.0.0.1\n</IfModule>\n',0o644))
        desired[str(native.GLOBAL)]=routing.CONFIG/'origins.conf'
    for site in next_config['sites'].values():
        if not site['enabled'] or site['error']:continue
        target=routing.CONFIG/(site['id']+'.conf')
        changes.append(own_file(target,routing.domain(site,next_config['gateway'],timeouts.settings(next_config))))
        for domain in site['custom_domains']:
            desired[str(native.CUSTOM/(domain+'.conf'))]=target
            desired[str(native.APACHE_CUSTOM/(domain+'.conf'))]=routing.CONFIG/'client-ip.conf'
    for path in sorted(set(previous.get('manifest',{}))|set(desired)):
        target=desired.get(path) or Path(previous['manifest'][path]['target'])
        change,entry=routing.pointer(path,target,previous.get('manifest',{}),path in desired)
        if change['before']!=change['after']:changes.append(change)
        if path in desired:manifest[path]=dict(entry,target=str(target))
    next_config['manifest']=manifest
    return changes

def restore(journal):
    for change in reversed(journal['changes']):routing.replace(change,reverse=True)
    if journal.get('active_before') is not None:service.write_vcl(service.ACTIVE,journal['active_before'])
    if journal['previous'].get('installed'):
        if not service.running():
            if not service.UNIT.exists():
                state.write(service.UNIT,service.unit().encode());service.UNIT.chmod(0o644);native.run('systemctl','daemon-reload')
            elif native.read(service.UNIT).decode()!=service.unit():raise ValueError('The owned service unit was changed')
            native.run('systemctl','enable','--now','varnish-for-webuzo');service.wait()
        if journal.get('old_vcl'):
            try:service.admin('vcl.use',journal['old_vcl'])
            except RuntimeError:
                # A service restart may have discarded the previous runtime name.
                _,candidate=service.load(journal['active_before']);service.admin('vcl.use',candidate)
    reload_servers()
    if not journal['previous'].get('installed'):service.stop()
    state.save(SETTINGS,journal['previous'])

def recover():
    cache_size.recover(SETTINGS)
    journal=state.read(JOURNAL)
    if journal:
        restore(journal);JOURNAL.unlink()

def apply(previous,next_config):
    if next_config.get('installed'):next_config['proxy_timeouts']=native.proxy_timeouts()
    changes=plans(previous,next_config)
    content=policy.render(next_config['sites'],next_config['gateway'],next_config['origin'],next_config)
    journal=dict(previous=previous,changes=changes,active_before=native.read(service.ACTIVE).decode() if service.ACTIVE.exists() else None,old_vcl=None)
    state.save(JOURNAL,journal)
    try:
        if next_config.get('installed'):
            if previous.get('installed'):
                journal['old_vcl'],candidate=service.load(content);state.save(JOURNAL,journal)
                service.admin('vcl.use',candidate)
            else:
                service.write_vcl(service.ACTIVE,content)
                native.run('systemctl','enable','--now','varnish-for-webuzo')
                service.wait()
            for sid,site in next_config['sites'].items():
                old=previous.get('sites',{}).get(sid,{})
                changed=any(old.get(k,'' if k in ('recv_vcl','backend_vcl') else None)!=site.get(k,'' if k in ('recv_vcl','backend_vcl') else None) for k in ('enabled','ttl','bypass','names','recv_vcl','backend_vcl'))
                changed=changed or profiles.selected(old)!=profiles.selected(site) or profiles.rules(previous,profiles.selected(site))!=profiles.rules(next_config,profiles.selected(site))
                if site.get('enabled') and changed:service.purge(site)
        for change in changes:routing.replace(change)
        reload_servers()
        if next_config.get('installed'):connections.wait(next_config)
        if next_config.get('installed'):service.write_vcl(service.ACTIVE,content)
        else:service.stop()
        state.save(SETTINGS,next_config);JOURNAL.unlink()
    except Exception:
        restore(journal);JOURNAL.unlink();raise
    if next_config.get('installed'):service.prune()

def reload_servers():
    native.run(native.NGINX,'-t');native.run(native.APACHE,'-t')
    native.run(native.APACHE,'graceful');native.run(native.NGINX,'-s','reload')

def validate_vcl(sites,config,sid=None):
    validation=copy.deepcopy(sites)
    if sid:validation[sid]['enabled']=True
    compile_config=dict(config,proxy_timeouts=native.proxy_timeouts())
    _,candidate=service.load(policy.render(validation,config['gateway'],config['origin'],compile_config))
    service.admin('vcl.discard',candidate)
    path=routing.CONFIG/'generations'/(candidate+'.vcl');state.trusted(path);path.unlink()

def action(request):
    if request.get('actor')!='root' or request.get('admin') is not True:raise ValueError('Webuzo administrator access is required')
    operation=request.get('action')
    allowed={'status','install','configure','purge','reconcile','start','remove','usage','resize','connection','connection_setup','vcl','defaults','profile_rules'}
    if operation not in allowed:raise ValueError('Unknown action')
    fields={'configure':{'id','enabled','ttl','bypass','profile','recv_vcl','backend_vcl'},'purge':{'id'},'connection':{'id'},'connection_setup':{'port'},'vcl':{'id','profile','recv_vcl','backend_vcl'},'resize':{'memory_mb'},'defaults':{'profile'},'profile_rules':{'profile','recv_vcl','backend_vcl'}}
    allowed_keys={'actor','admin','action'}|fields.get(operation,set())
    if set(request)-allowed_keys:raise ValueError('Unexpected request field')
    with state.locked():
        recover()
        if operation=='status':return status()
        previous=settings();sites=inventory(previous)
        if operation in ('usage','resize','connection','vcl') and not previous.get('installed'):raise ValueError('Install the Varnish service first')
        if operation=='usage':return dict(usage=service.usage(previous))
        if operation=='resize':
            changed=cache_size.resize(previous,request.get('memory_mb'),SETTINGS)
            return dict(status(),message='Cache size saved. Varnish restarted and the shared cache was cleared.' if changed else 'Cache size is unchanged; Varnish was not restarted.')
        if operation=='remove':
            remove_setup(previous);return dict(status(),message='Varnish setup removed. Sites now use their native Webuzo routing.')
        if operation=='start':
            if not previous.get('installed') or not service.UNIT.exists() or native.read(service.UNIT).decode()!=service.unit():raise ValueError('Install the owned service first')
            native.run('systemctl','start','varnish-for-webuzo');service.wait();return dict(status(),message='Varnish is running')
        config=copy.deepcopy(previous);config.update(sites=sites)
        if operation=='install':
            if previous.get('installed'):raise ValueError('The service is already installed')
            service.prepare();config.update(installed=True,gateway=secrets.token_hex(32),origin=secrets.token_hex(32))
            for site in sites.values():site['token']=secrets.token_hex(32)
        else:
            if not previous.get('installed'):raise ValueError('Install the Varnish service first')
            if operation=='defaults':config['default_profile']=profiles.name(request.get('profile'))
            if operation=='profile_rules':
                profile=profiles.name(request.get('profile'))
                row={field:request.get(field) for field in ('recv_vcl','backend_vcl')}
                config.setdefault('profile_rules',{})[profile]=row
                profiles.rules(config,profile);validate_vcl(sites,config)
            if operation in ('configure','purge','connection','vcl'):
                sid=state.identity(request.get('id'))
                if sid not in sites:raise ValueError('Unknown site')
                site=sites[sid]
                if operation=='connection':
                    if sid not in previous.get('sites',{}):raise ValueError('Save the site settings first')
                    details=connections.details(site,previous)
                    details['ready']=details['ready'] and service.running()
                    return dict(connection=details)
                if operation=='vcl':
                    if site['error']:raise ValueError(site['error'])
                    site['profile']=profiles.name(request.get('profile',site['profile']))
                    for field,stage in (('recv_vcl','recv'),('backend_vcl','backend_response')):
                        source=request.get(field)
                        fragments.validate(source,stage);site[field]=source
                    # Compile even for a disabled site, without enabling its public routing.
                    validate_vcl(sites,config,sid)
                if operation=='purge':
                    if not site['enabled']:raise ValueError('Varnish is not enabled for this site')
                    service.purge(site);return dict(message='Site cache cleared')
                if operation=='configure':
                    if type(request.get('enabled')) is not bool:raise ValueError('Invalid enabled value')
                    if type(request.get('ttl')) is not int or not 1<=request['ttl']<=2147483647:raise ValueError('Use a positive cache lifetime within the supported integer range')
                    if site['error'] and request['enabled']:raise ValueError(site['error'])
                    site.update(enabled=request['enabled'],ttl=request['ttl'],bypass=policy.paths(request.get('bypass',[])))
                    site['profile']=profiles.name(request.get('profile',site['profile']))
                    if any(field in request for field in ('recv_vcl','backend_vcl')):
                        for field,stage in (('recv_vcl','recv'),('backend_vcl','backend_response')):
                            source=request.get(field,site[field]);fragments.validate(source,stage);site[field]=source
                        if site['error']:raise ValueError(site['error'])
                        validate_vcl(sites,config,sid)
        if operation in ('install','reconcile','connection_setup'):
            connections.prepare(previous,config,request.get('port',config.get('control_port',connections.DEFAULT_PORT)))
        if operation=='configure':credentials.change(site,site['enabled'])
        apply(previous,config)
        return dict(status(),message={'install':'Varnish is ready. Enable the desired sites below.','configure':'Site profile and settings saved.','vcl':'Site VCL validated and applied.','reconcile':'Site list refreshed.','connection_setup':'Local HTTP connection saved. Show connection information in the site row for the application settings.','defaults':'Default profile saved. Existing sites keep their assigned profile.','profile_rules':'Central profile rules validated and applied to sites using this profile.'}[operation])

def remove():
    with state.locked():
        recover();remove_setup(settings())

def remove_setup(previous):
    if previous.get('installed'):
        config=copy.deepcopy(previous);config['installed']=False
        for site in config['sites'].values():site['enabled']=False
        apply(previous,config)
        for site in previous['sites'].values():
            try:credentials.change(site,False)
            except (KeyError,RuntimeError):pass  # Account-controlled files cannot prevent global deactivation; the capability is revoked by VCL/service removal.
