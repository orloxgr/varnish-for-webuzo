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
import browser_cache
import repository
import recognition
import cookie_views
import cookie_bridge
import cookie_execution
import cms_discovery
import aggressive
import cms_inventory
import cms_resolver

SETTINGS=state.ROOT/'settings.json'
JOURNAL=state.ROOT/'transaction.json'

def settings():return state.read(SETTINGS,{})

def inventory(config,discover=False,discover_id=None):
    sites=native.collect()
    for sid,site in sites.items():
        previous=config.get('sites',{}).get(sid,{})
        site['profile']=profiles.selected(previous) if sid in config.get('sites',{}) else profiles.default(config)
        site.update(enabled=bool(previous.get('enabled')) and not bool(site['error']),token=previous.get('token') or secrets.token_hex(32),bypass=previous.get('bypass',[]))
        site.update(recv_vcl=previous.get('recv_vcl',''),backend_vcl=previous.get('backend_vcl',''))
        site['browser_cache']=browser_cache.validate(previous['browser_cache']) if previous.get('browser_cache') is not None else None
        site['cookie_policies']=cookie_views.normalize(previous.get('cookie_policies'))
        site['cookie_integration']=copy.deepcopy(previous.get('cookie_integration'))
        site.update(aggressive.settings(previous))
        if (discover or sid==discover_id) and site.get('path'):
            site['cms_installations'],site['cms_discovery_notices'],site['cms_sessions']=cms_inventory.discover(site,previous)
        else:
            site['cms_installations']=copy.deepcopy(previous.get('cms_installations',[]))
            site['cms_discovery_notices']=copy.deepcopy(previous.get('cms_discovery_notices',[]))
            site['cms_sessions']=copy.deepcopy(previous.get('cms_sessions',[]))
        if site['cookie_integration'] is not None:
            site['cookie_integration'],revoked=cookie_bridge.cookie_control.reconcile_integration(site['cookie_integration'],site['domain'],site['names'])
            if revoked or previous.get('cookie_integration_notice'):
                site['cookie_integration_notice']='The previous WordPress endpoint is no longer assigned to this website. The connection was disabled.'
    return sites

def status():
    config=settings();sites=inventory(config)
    return dict(installed=bool(config.get('installed')),package=service.installed(),running=service.running(),memory_mb=config.get('memory_mb',256),
                default_profile=profiles.default(config),profiles=profiles.catalog(config),proxy_timeouts=timeouts.settings(config) if 'proxy_timeouts' in config else None,control_port=config.get('control_port'),
                browser_cache=browser_cache.defaults(config),browser_cache_profiles=copy.deepcopy(browser_cache.PROFILE_PATHS),
                cookie_recognition=recognition.status(),
                sites=[{k:v for k,v in s.items() if k not in ('token','uid','gid','home','custom_domains','credential_roots')} for s in sites.values()])

def own_file(path,value,mode=0o600):
    raw=native.read(path).decode() if path.exists() or path.is_symlink() else None
    return dict(path=str(path),before=raw,after=value,mode=mode)

def plans(previous,next_config):
    changes=[];manifest={};desired={}
    if next_config.get('installed'):
        changes.append(own_file(routing.CONFIG/'origins.conf',routing.origins(next_config['origin'],timeouts.settings(next_config))+connections.render(next_config)+browser_cache.maps(next_config['sites'],next_config)))
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
    cookie_invalidations=set(journal.get('cookie_purge_sites',[])) if journal.get('cookie_activation_attempted') else set()
    cookie_invalidations.update(item['site'] for item in journal.get('cookie_operations',[])
        if item['phase'] in ('committing','committed') and item['base_digest']!=item['target_digest'])
    if journal.get('local_started',True):
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
                    _,candidate=service.load(journal.get('runtime_before') or journal['active_before']);service.admin('vcl.use',candidate)
        if journal['changes']:reload_servers()
        if not journal['previous'].get('installed'):service.stop()
        journal['local_started']=False;state.save(JOURNAL,journal)
    if journal.get('cms_resolver_before') is not None:cms_resolver.restore(journal['cms_resolver_before'])
    cookie_bridge.rollback(journal,lambda value:state.save(JOURNAL,value))
    newer=cookie_bridge.preserved_newer(journal)
    if newer:state.save(state.ROOT/'last-cookie-rollback.json',{'preserved_newer_application_policy':newer})
    for identity in cookie_invalidations:
        old=journal['previous'].get('sites',{}).get(identity)
        if old and old.get('enabled') and journal['previous'].get('installed') and service.running():service.purge(old)
    if journal.get('candidate') and service.running():
        try:service.prune()
        except (OSError,ValueError,RuntimeError):
            import syslog
            syslog.syslog(syslog.LOG_WARNING,'Varnish for Webuzo: unused candidate cleanup failed after rollback; the working policy was restored.')
    state.save(SETTINGS,journal['previous'])

def recover():
    cache_size.recover(SETTINGS)
    journal=state.read(JOURNAL)
    if journal:
        restore(journal);JOURNAL.unlink()

def apply(previous,next_config,cookie_force_sites=()):
    next_config['cookie_defaults_version']=cookie_views.default_version()
    next_config['cookie_defaults_digest']=cookie_views.default_digest()
    if next_config.get('installed'):next_config['proxy_timeouts']=native.proxy_timeouts()
    changes=[change for change in plans(previous,next_config) if change['before']!=change['after']]
    content=policy.render(next_config['sites'],next_config['gateway'],next_config['origin'],next_config)
    runtime_before=service.current_source()[1] if previous.get('installed') else None
    native_changed=runtime_before is None or content.rstrip('\n')!=runtime_before.rstrip('\n')
    cookie_purge_sites=[]
    execution=cookie_execution.projections()
    for sid,site in next_config['sites'].items():
        old=previous.get('sites',{}).get(sid,{})
        changed=(previous.get('cookie_defaults_digest')!=next_config.get('cookie_defaults_digest') or
                 execution(previous.get('cookie_policies'),old.get('cookie_policies'))!=execution(next_config.get('cookie_policies'),site.get('cookie_policies')))
        changed=changed or cookie_bridge.configuration(old.get('cookie_integration'),old or site)!=cookie_bridge.configuration(site.get('cookie_integration'),site)
        if changed and site.get('enabled'):cookie_purge_sites.append(sid)
    journal=dict(previous=previous,changes=changes,active_before=native.read(service.ACTIVE).decode() if service.ACTIVE.exists() else None,old_vcl=None,
                 cookie_operations=cookie_bridge.plan(previous,next_config,cookie_force_sites),cookie_purge_sites=cookie_purge_sites,cookie_activation_attempted=False,local_started=False,runtime_before=runtime_before)
    if cms_resolver.selected(previous) or cms_resolver.selected(next_config):journal['cms_resolver_before']=cms_resolver.snapshot()
    state.save(JOURNAL,journal)
    try:
        cms_resolver.prepare(next_config)
        cookie_bridge.prepare(journal,lambda value:state.save(JOURNAL,value))
        journal['cookie_purge_sites']=sorted(set(journal['cookie_purge_sites'])|{item['site'] for item in journal['cookie_operations'] if item['base_digest']!=item['target_digest']})
        cookie_purge_sites=journal['cookie_purge_sites'];state.save(JOURNAL,journal)
        if next_config.get('installed'):
            if previous.get('installed'):
                if native_changed:
                    journal['old_vcl'],candidate=service.load(content);journal['candidate']=candidate;state.save(JOURNAL,journal)
                cookie_bridge.commit(journal,lambda value:state.save(JOURNAL,value))
                if native_changed:
                    journal.update(cookie_activation_attempted=True,local_started=True);state.save(JOURNAL,journal)
                    service.admin('vcl.use',candidate)
            else:
                journal['local_started']=True;state.save(JOURNAL,journal)
                service.write_vcl(service.ACTIVE,content)
                cookie_bridge.commit(journal,lambda value:state.save(JOURNAL,value))
                journal['cookie_activation_attempted']=True;state.save(JOURNAL,journal)
                native.run('systemctl','enable','--now','varnish-for-webuzo')
                service.wait()
            for sid,site in next_config['sites'].items():
                old=previous.get('sites',{}).get(sid,{})
                changed=any(old.get(k,'' if k in ('recv_vcl','backend_vcl') else None)!=site.get(k,'' if k in ('recv_vcl','backend_vcl') else None) for k in ('enabled','bypass','names','recv_vcl','backend_vcl'))
                changed=changed or old.get('cms_installations',[])!=site.get('cms_installations',[])
                changed=changed or old.get('cms_sessions',[])!=site.get('cms_sessions',[])
                changed=changed or aggressive.settings(old)!=aggressive.settings(site)
                changed=changed or execution(previous.get('cookie_policies'),old.get('cookie_policies'))!=execution(next_config.get('cookie_policies'),site.get('cookie_policies'))
                changed=changed or sid in cookie_purge_sites
                changed=changed or profiles.selected(old)!=profiles.selected(site) or profiles.rules(previous,profiles.selected(site))!=profiles.rules(next_config,profiles.selected(site))
                if site.get('enabled') and changed:service.purge(site)
        if changes:
            journal['local_started']=True;state.save(JOURNAL,journal)
            for change in changes:routing.replace(change)
            reload_servers()
        if next_config.get('installed'):connections.wait(next_config)
        if next_config.get('installed'):
            if content!=journal['active_before']:service.write_vcl(service.ACTIVE,content)
        else:
            journal['local_started']=True;state.save(JOURNAL,journal)
            service.stop()
        if journal.get('cms_resolver_before') is not None:cms_resolver.finish(next_config)
        state.save(SETTINGS,next_config);JOURNAL.unlink()
    except Exception:
        restore(journal);JOURNAL.unlink()
        if cookie_bridge.preserved_newer(journal):
            raise cookie_bridge.cookie_control.ControlError('Cookie policy update failed. Newer WordPress cookie settings were preserved.') from None
        raise
    if next_config.get('installed'):service.prune()

def reload_servers():
    native.run(native.NGINX,'-t');native.run(native.APACHE,'-t')
    native.run(native.APACHE,'graceful');native.run(native.NGINX,'-s','reload')


def apply_cookie_only(previous,config,cookie_force_sites=()):
    """A retained panel can sync WordPress without installing/starting a proxy."""
    config['cookie_defaults_version']=cookie_views.default_version()
    config['cookie_defaults_digest']=cookie_views.default_digest()
    operations=cookie_bridge.plan(previous,config,cookie_force_sites)
    journal=dict(previous=previous,changes=[],active_before=None,old_vcl=None,
                 cookie_operations=operations,local_started=False,cookie_purge_sites=[])
    state.save(JOURNAL,journal)
    try:
        cookie_bridge.prepare(journal,lambda value:state.save(JOURNAL,value))
        cookie_bridge.commit(journal,lambda value:state.save(JOURNAL,value))
        state.save(SETTINGS,config);JOURNAL.unlink()
    except Exception:
        restore(journal);JOURNAL.unlink()
        if cookie_bridge.preserved_newer(journal):
            raise cookie_bridge.cookie_control.ControlError('Cookie policy update failed. Newer WordPress cookie settings were preserved.') from None
        raise
    return bool(operations)

def validate_vcl(sites,config,sid=None):
    validation=copy.deepcopy(sites)
    if sid:validation[sid]['enabled']=True
    compile_config=dict(config,proxy_timeouts=native.proxy_timeouts())
    _,candidate=service.load(policy.render(validation,config['gateway'],config['origin'],compile_config))
    service.admin('vcl.discard',candidate)
    path=routing.CONFIG/'generations'/(candidate+'.vcl');state.trusted(path);path.unlink()

def action(request):
    if request.get('action') in ('cookie_policies_status','cookie_policies_save','cookie_integration_status'):
        return cookie_policy_action(request)
    if request.get('actor')!='root' or request.get('admin') is not True:raise ValueError('Webuzo administrator access is required')
    operation=request.get('action')
    allowed={'status','install','configure','purge','reconcile','start','remove','usage','resize','connection','connection_setup','vcl','defaults','profile_rules','browser_defaults','browser_site','browser_restore','recognition_status','recognition_configure','recognition_update'}
    if operation not in allowed:raise ValueError('Unknown action')
    fields={'configure':{'id','enabled','bypass','profile','recv_vcl','backend_vcl','aggressive','aggressive_ttl'},'purge':{'id'},'connection':{'id'},'connection_setup':{'port'},'vcl':{'id','profile','recv_vcl','backend_vcl'},'resize':{'memory_mb'},'defaults':{'profile'},'profile_rules':{'profile','recv_vcl','backend_vcl'},'browser_defaults':{'settings'},'browser_site':{'id','settings'}}
    allowed_keys={'actor','admin','action'}|fields.get(operation,set())
    if operation=='recognition_configure':allowed_keys.add('automatic')
    if set(request)-allowed_keys:raise ValueError('Unexpected request field')
    # Bundled database status does not enter site inventory or cache transactions.
    if operation in ('recognition_status','recognition_configure','recognition_update'):
        result=recognition.status()
        return dict(cookie_recognition=result,message=result['message'])
    with state.locked():
        recover()
        if operation=='status':return status()
        previous=settings();sites=inventory(previous,discover=operation in ('install','reconcile'),discover_id=request.get('id') if operation=='configure' else None)
        if operation=='reconcile' and previous.get('installed'):
            repository.reconcile_owned()
            repository.ensure_cookie_modules()
            repository.ensure_cookie_handoff()
            service.configure_esi(previous.get('memory_mb',256))
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
            if operation=='browser_restore':
                config['browser_cache']=browser_cache.defaults({})
                for site in sites.values():site['browser_cache']=None
            if operation=='browser_defaults':config['browser_cache']=browser_cache.validate(request.get('settings'))
            if operation=='profile_rules':
                profile=profiles.name(request.get('profile'))
                row={field:request.get(field) for field in ('recv_vcl','backend_vcl')}
                config.setdefault('profile_rules',{})[profile]=row
                profiles.rules(config,profile);validate_vcl(sites,config)
            if operation in ('configure','purge','connection','vcl','browser_site'):
                sid=state.identity(request.get('id'))
                if sid not in sites:raise ValueError('Unknown site')
                site=sites[sid]
                if operation=='browser_site':
                    if 'settings' not in request:raise ValueError('Browser cache settings are required')
                    site['browser_cache']=None if request['settings'] is None else browser_cache.validate(request['settings'])
                    if site['error']:raise ValueError(site['error'])
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
                    if site['error'] and request['enabled']:raise ValueError(site['error'])
                    site.update(enabled=request['enabled'],bypass=policy.paths(request.get('bypass',[])))
                    site.update(aggressive.settings(dict(site,**{k:request[k] for k in ('aggressive','aggressive_ttl') if k in request})))
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
        return dict(status(),message={'install':'Varnish is ready. Enable the desired sites below.','configure':'Site profile and settings saved.','vcl':'Site VCL validated and applied.','reconcile':'Site list refreshed.','connection_setup':'Local HTTP connection saved. Show connection information in the site row for the application settings.','defaults':'Default profile saved. Existing sites keep their assigned profile.','profile_rules':'Central profile rules validated and applied to sites using this profile.','browser_defaults':'Browser cache defaults applied to sites using the central settings. Existing browser copies expire under their previous policy.','browser_site':'Browser cache settings saved for this site. Existing browser copies expire under their previous policy.','browser_restore':'Browser cache defaults restored and applied to all enabled sites: 30 days for ordinary assets and one year for versioned assets. Custom browser patterns and site overrides were cleared.'}[operation])

def cookie_policy_action(request):
    cookie_views.allowed(request)
    saving=request['action']=='cookie_policies_save'
    permitted={'actor','admin','action','id'}|({'settings','integration'} if saving else {'integration'} if request['action']=='cookie_integration_status' else set())
    if set(request)-permitted:raise ValueError('Unexpected cookie policy request field')
    with state.locked():
        if saving:recover()
        previous=settings();sites=inventory(previous)
        identity,_=cookie_views.scope(request,sites,saving=saving)
        config=copy.deepcopy(previous);config['sites']=sites
        if saving and not cookie_views.administrator(request):
            # Ownership is checked against fresh inventory, but an account's
            # cookie save is not a global domain-reconciliation operation.
            config['sites']=copy.deepcopy(previous.get('sites',{}))
            config['sites'][identity]=sites[identity]
        if request['action']=='cookie_integration_status':
            if identity is None:raise ValueError('Choose a site for its WordPress connection')
            return dict(cookie_integration=cookie_bridge.status(sites[identity],request.get('integration'),config))
        if saving:
            if 'settings' not in request:raise ValueError('Cookie policy settings are required')
            selected=cookie_views.normalize(request['settings'])
            if identity is None:config['cookie_policies']=selected
            else:sites[identity]['cookie_policies']=selected
            if 'integration' in request:
                if identity is None:raise ValueError('WordPress connections are configured per site')
                sites[identity]['cookie_integration']=cookie_bridge.configuration(request['integration'],sites[identity])
                sites[identity].pop('cookie_integration_notice',None)
            try:
                force_sites=tuple(config['sites']) if identity is None else (identity,)
                if config.get('installed'):apply(previous,config,cookie_force_sites=force_sites)
                else:apply_cookie_only(previous,config,cookie_force_sites=force_sites)
            except Exception as error:
                if cookie_views.administrator(request):raise
                if isinstance(error,cookie_bridge.cookie_control.ControlError):raise
                raise RuntimeError('The cookie policy could not be applied. The previous policy was restored; contact the hosting administrator.') from None
        result=cookie_views.view(config,sites,dict(request,id=identity))
        if saving:
            active=result['cookie_policies']['enabled']
            linked=any(row.get('cookie_integration',{}).get('enabled') for row in sites.values() if row.get('cookie_integration') and (identity is None or row['id']==identity))
            result['message']=('Cookie policies validated and applied.' if active else
                'Cookie policies saved through the configured UltraCache connection. Varnish is disabled for this scope.' if linked else
                'Cookie policies saved. They will apply when Varnish is enabled for this scope.')
        return result


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
