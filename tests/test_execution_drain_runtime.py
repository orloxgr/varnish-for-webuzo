"""Actual native dispatch owner; MOCK metadata worker/drain, no real PHP claim."""
import copy,json,os,shutil,unittest
import test_mutation_backend as backend
import test_mutation_coverage_runtime as coverage
import test_reuse_authority as authority
from test_cookie_delivery import proxy,cookies
from test_public_selection_runtime import control
from test_mutation_wire import json_header
from test_execution_drain_wire import for_execution,signed

PATH='/wp-admin/admin-ajax.php?action=owned_read'
@unittest.skipUnless(shutil.which('varnishd') and os.environ.get('SCP_EXPERIMENTAL_REUSE_TEST')=='1','Matching native engine required')
class NativeExecutionDrain(unittest.TestCase):
    call=authority.NativeReuseAuthority.call
    observe=authority.NativeReuseAuthority.observe
    recover=authority.NativeReuseAuthority.recover
    publish=authority.NativeReuseAuthority.publish
    ready=authority.NativeReuseAuthority.ready
    ended=backend.NativeMutationBackend.ended
    drain=coverage.NativeCoverageHolds.drain
    def register(self,get,enabled=True):
        extra={'X-UltraCache-Public-Selection-Reuse-Version':'1','X-UltraCache-Public-Selection-Reuse-Policy':authority.REUSE_POLICY,
               'X-UltraCache-Public-Selection-Coverage-Version':'1','X-UltraCache-Public-Selection-Coverage-Policy':coverage.POLICY}
        if enabled:extra['X-UltraCache-Public-Selection-Execution-Drain-Version']='1'
        status,h,b=control(get,enabled=True,names='',extra=extra)
        self.assertEqual(status,200,(status,b))
        self.assertEqual(h.get('X-UltraCache-VCL-Public-Selection-Execution-Drain-Version'),'1' if enabled else None)
    def dispatch(self,get,original,*,change=None,token=True):
        value=for_execution(original,target=PATH)
        if change:change(value)
        value=signed(value,coverage.KEY)
        return control(get,'private-execution-drain-dispatch',token=token,extra={
            'X-UltraCache-Delivery-Execution-Drain-Context':json_header(value).decode(),
            'Cookie':'private=do-not-forward','Authorization':'Basic do-not-forward','X-Forged':'do-not-forward'})
    def test_owned_metadata_request_skips_new_hold_and_diagnostic_never_retires_original(self):
        seen=[];workers=[]
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='execution-drain':
                workers.append(dict(headers));self.assertEqual(path,PATH)
                for name in ('Cookie','Authorization','X-Forged','X-UltraCache-Mutation-Context','X-UltraCache-Token','X-UltraCache-Delivery-Manifest'):
                    self.assertNotIn(name,headers)
                self.assertEqual(headers['X-UltraCache-Delivery-Authorization'],'b'*64)
                self.assertEqual(headers['X-UltraCache-Delivery-Version'],'1')
                self.assertEqual(headers['X-UltraCache-Delivery-Execution-Drain-Version'],'1')
                self.assertEqual(headers['X-UltraCache-Delivery-Original-URL'],PATH)
                self.assertEqual(headers['X-UltraCache-Delivery-Public-Selection-Scope'],'/')
                return 204,'',[('X-UltraCache-Execution-Drain-Version','1'),('X-UltraCache-Execution-Drain-Outcome','settled'),('Set-Cookie','must-not-replay=1')]
            c=coverage.context(self,headers,'POST',path);seen.append(c)
            self.assertEqual(headers.get('X-UltraCache-VCL-Execution-Drain-Version'),'1')
            return 'original body',[('Cache-Control','private, no-store'),coverage.response_receipt(c)]
        with proxy('ultracache',origin,allow_post=True) as get:
            self.register(get);old=self.ready(get);self.assertEqual(backend.post(get,PATH)[0],200);self.ended(get)
            status,h,b=self.dispatch(get,seen[0]);self.assertEqual(status,204,(status,h,b));self.assertEqual(b,b'')
            self.assertFalse(cookies(list(h.items())));self.assertIn('no-store',h['Cache-Control'])
            current=self.observe(get);self.assertEqual(current['temporaryHolds'],1)
            self.assertEqual(len(current['unsettledExecutions']),1);self.assertEqual(current['scopeRevision'],old['scopeRevision'])
            self.drain(get,seen[0]);self.assertEqual(self.observe(get)['scopeState'],'ready')
            # Lost ACK retry can reconcile its exact producer journal; never a
            # native fact that the original body is reusable or the journal ended.
            self.assertEqual(self.dispatch(get,seen[0])[0],204)
            self.assertEqual(self.observe(get).get('temporaryHolds',0),0);self.assertEqual(len(workers),2)
    def test_invalid_dispatch_auth_schema_original_identity_and_phase_never_fall_into_application(self):
        seen=[]
        def origin(path,headers):
            c=coverage.context(self,headers,'POST',path);seen.append(c)
            return 'ordinary',[('Cache-Control','private, no-store'),coverage.response_receipt(c)]
        with proxy('ultracache',origin,allow_post=True) as get:
            self.register(get);self.ready(get);backend.post(get,PATH);self.ended(get)
            self.assertEqual(self.dispatch(get,seen[0],token=False)[0],403)
            status,_,_=control(get,'private-execution-drain-dispatch',token=False,extra={'X-Webuzo-Varnish-Token':'b'*64})
            self.assertEqual(status,403,'A different control operation must not become a generic site purge')
            self.assertEqual(self.dispatch(get,seen[0],change=lambda v:v['execution'].update(challenge='f'*64))[0],409)
            self.assertEqual(self.dispatch(get,seen[0],change=lambda v:v.update(extra=True))[0],400)
            self.assertEqual(get(PATH,extra={'X-UltraCache-Delivery-Phase':'execution-drain'})[0],400)
            self.assertEqual(len(seen),1);self.assertEqual(self.observe(get)['temporaryHolds'],1)
    def test_bad_metadata_response_is_not_forwarded_and_does_not_create_another_execution(self):
        seen=[]
        def origin(path,headers):
            if headers.get('X-UltraCache-Delivery-Phase')=='execution-drain':
                return 'untrusted application HTML',[('Cache-Control','public, max-age=999')]
            c=coverage.context(self,headers,'POST',path);seen.append(c)
            return 'original',[('Cache-Control','private, no-store'),coverage.response_receipt(c)]
        with proxy('ultracache',origin,allow_post=True) as get:
            self.register(get);self.ready(get);backend.post(get,PATH);self.ended(get)
            status,h,b=self.dispatch(get,seen[0]);self.assertEqual(status,503)
            self.assertNotIn(b'untrusted application HTML',b)
            self.assertEqual(len(self.observe(get)['unsettledExecutions']),1)
    def test_dispatch_and_origin_hint_require_explicit_matching_negotiation(self):
        seen=[]
        def origin(path,headers):
            self.assertNotIn('X-UltraCache-VCL-Execution-Drain-Version',headers)
            c=coverage.context(self,headers,'POST',path);seen.append(c)
            return 'legacy covered origin',[('Cache-Control','private, no-store'),coverage.response_receipt(c)]
        with proxy('ultracache',origin,allow_post=True) as get:
            self.register(get,enabled=False);self.ready(get);backend.post(get,PATH);self.ended(get)
            self.assertEqual(self.dispatch(get,seen[0])[0],409)
            status,_,_=control(get,enabled=True,names='',extra={
                'X-UltraCache-Public-Selection-Execution-Drain-Version':'2'})
            self.assertEqual(status,400)
            self.assertEqual(len(seen),1);self.assertEqual(self.observe(get)['temporaryHolds'],1)

if __name__=='__main__':unittest.main()
