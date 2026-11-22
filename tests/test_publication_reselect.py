"""A verified early conflict retires only its old parent before one new selection."""
import base64
import hashlib
import json
import shutil
import subprocess
import unittest
from urllib.parse import quote
from test_cookie_delivery import proxy,cookies
from test_cms_cookie_choices import cache
from test_cold_public_selection import Application,choices
from test_public_selection_runtime import control
from test_delivery_continuation import BODY,envelope

class Publications(Application):
    def __init__(self):
        super().__init__(private=True)
        self.generations={};self.observed=[];self.providers=[];self.corrupt=None
        self.reason='publication-binding-mismatch';self.reject_selection=False
    def publication(self,path,host='example.test'):
        body=BODY.replace('parent[',self.generations.get(host+path,self.generations.get(path,'A'))+'[')
        token='mock.'+hashlib.sha256((path+'|'+body).encode()).hexdigest()
        return body,token
    def conflict(self,path,headers):
        assert headers.get('X-UltraCache-VCL-Publication-Reselect-Version')=='1'
        fields=[('Cache-Control','private, no-store'),('Surrogate-Control','no-store'),
          ('X-UltraCache-Delivery-Conflict-Version','1'),
          ('X-UltraCache-Delivery-Conflict',self.reason),
          ('X-UltraCache-Delivery-Request',headers['X-UltraCache-Delivery-Request']),
          ('X-UltraCache-Delivery-Original-URL',headers['X-UltraCache-Delivery-Original-URL']),
          ('X-UltraCache-Delivery-Manifest-SHA256',hashlib.sha256(headers['X-UltraCache-Delivery-Manifest'].encode()).hexdigest())]
        body=''
        if self.corrupt=='body':body='not an early empty conflict'
        elif self.corrupt=='cookie':fields.append(('Set-Cookie','already-consumed=1'))
        elif self.corrupt=='encoding':fields.append(('Content-Encoding','gzip'))
        elif self.corrupt:
            name,mode=self.corrupt
            key=next(i for i,(k,v) in enumerate(fields) if k==name)
            if mode=='missing':fields.pop(key)
            elif mode=='duplicate':fields.append(fields[key])
            else:fields[key]=(name,'wrong')
        return 409,body,fields
    def __call__(self,path,headers):
        phase=headers.get('X-UltraCache-Delivery-Phase')
        self.observed.append((path,phase,headers.get('Cookie'),headers.get('Accept')))
        body,token=self.publication(path,headers.get("Host","example.test"))
        if phase=='prepare':
            if headers.get('X-UltraCache-Delivery-Manifest')!=token:return self.conflict(path,headers)
            self.providers.append((path,phase))
            return envelope(headers,headers.get('X-Test-Visitor','guest')),[('Cache-Control','private, no-store'),('X-UltraCache-Delivery-Outcome','verified')]
        if phase=='public-select':
            if self.reject_selection:
                fields=[('Cache-Control','private, no-store')]
                if self.reject_selection=='declared':
                    fields += [('Content-Type','application/vnd.ultracache.delivery+json'),
                               ('X-UltraCache-Delivery-Public-Selection-Version','1'),
                               ('X-UltraCache-Delivery-Conflict-Version','1'),
                               ('X-UltraCache-Delivery-Conflict','publication-binding-mismatch')]
                return 409,'',fields
            self.providers.append((path,phase))
            raw,fields=super().__call__(path,headers);output=json.loads(raw);selected=output['selectedPublic']
            selected['manifest']=token
            selected['publicParent'].update(generation=hashlib.sha256(body.encode()).hexdigest(),bodyBase64=base64.b64encode(body.encode()).decode())
            selected['headers']=[f for f in selected['headers'] if not f.startswith('X-UltraCache-Delivery-Prepare:')]
            selected['headers'].append('X-UltraCache-Delivery-Prepare: /index.php?ultracache_delivery='+quote(token,safe=''))
            return json.dumps(output),fields
        return 'plain public',[('Cache-Control','public, max-age=120')]

@unittest.skipUnless(shutil.which('varnishd'),'Native Varnish required')
class PublicationReselect(unittest.TestCase):
    def primed(self,get,app):
        self.assertEqual(control(get,enabled=True,names='')[0],200)
        status,fields,body=get('/race',extra={'Accept':'text/html','X-Test-Visitor':'A'})
        self.assertEqual((status,cache(fields)),(200,'MISS'))
        self.assertIn('A[',body)
        app.generations['/race']='B'
    def test_verified_conflict_selects_new_parent_once_and_next_visit_hits(self):
        for reason in ('publication-binding-mismatch','public-publication-unavailable'):
            app=Publications();app.reason=reason
            with self.subTest(reason=reason),proxy('ultracache',app,policies=choices(('shared_metric','shared'))) as get:
                self.primed(get,app)
                start=len(app.observed);providers=len(app.providers)
                status,fields,body=get('/race','shared_metric=B',{'Accept':'text/html','X-Test-Visitor':'B'})
                if status!=200:
                    log=subprocess.run(['varnishlog','-n',str(get.instance),'-d','-g','request','-i','VCL_Log,VCL_Error,RespReason'],capture_output=True,text=True)
                    self.fail(log.stdout[-5000:])
                self.assertEqual((status,cache(fields)),(200,'MISS'))
                self.assertIn('B[',body);self.assertIn('private:B',body);self.assertNotIn('private:A',body)
                self.assertEqual([p for _,p,_,_ in app.observed[start:]],['prepare','public-select'])
                self.assertEqual(len(app.providers)-providers,1)
                self.assertTrue(all(c=='shared_metric=B' for _,_,c,_ in app.observed[start:]))
                self.assertFalse(any('Conflict' in k or 'Manifest-SHA256' in k or 'Reselect-Version' in k for k,v in fields))
                status,fields,body=get('/race',extra={'Accept':'text/html','X-Test-Visitor':'C'})
                self.assertEqual((status,cache(fields)),(200,'HIT'));self.assertIn('private:C',body)
    def test_retirement_is_exact_url_and_publication(self):
        app=Publications()
        with proxy('ultracache',app) as get:
            self.primed(get,app)
            self.assertEqual(get('/untouched',extra={'Accept':'text/html'})[0],200)
            self.assertEqual(get('/race',extra={'Accept':'text/html'})[0],200)
            status,fields,_=get('/untouched',extra={'Accept':'text/html'})
            self.assertEqual((status,cache(fields)),(200,'HIT'))
    def test_incomplete_or_consumed_conflicts_never_retry(self):
        bad=[(name,mode) for name in ('X-UltraCache-Delivery-Conflict-Version','X-UltraCache-Delivery-Conflict',
              'X-UltraCache-Delivery-Request','X-UltraCache-Delivery-Original-URL','X-UltraCache-Delivery-Manifest-SHA256')
              for mode in ('missing','wrong','duplicate')]+['cookie','body','encoding']
        for case in bad:
            app=Publications();app.corrupt=case
            with self.subTest(case=case),proxy('ultracache',app) as get:
                self.primed(get,app);start=len(app.observed);providers=len(app.providers)
                status,fields,_=get('/race',extra={'Accept':'text/html'})
                self.assertEqual(status,503)
                self.assertEqual([p for _,p,_,_ in app.observed[start:]],['prepare'])
                self.assertEqual(len(app.providers),providers)
    def test_current_registry_and_restart_budget_are_required(self):
        for disabled,budget in ((True,4),(False,2)):
            app=Publications()
            with self.subTest(disabled=disabled,budget=budget),proxy('ultracache',app,daemon_parameters=('max_restarts='+str(budget),)) as get:
                self.primed(get,app)
                if disabled:self.assertEqual(control(get,enabled=False,names='')[0],200)
                count=len(app.providers);start=len(app.observed)
                self.assertEqual(get('/race',extra={'Accept':'text/html'})[0],503)
                self.assertEqual(len(app.providers),count)
                self.assertEqual([p for _,p,_,_ in app.observed[start:]],['prepare'])
    def test_later_selection_error_never_retries_and_preserves_raw_origin_status(self):
        for kind,expected in (('raw',409),('declared',503)):
            app=Publications()
            with self.subTest(kind=kind),proxy('ultracache',app) as get:
                self.primed(get,app);app.reject_selection=kind;start=len(app.observed)
                self.assertEqual(get('/race',extra={'Accept':'text/html'})[0],expected)
                self.assertEqual([p for _,p,_,_ in app.observed[start:]],['prepare','public-select'])
    def test_retirement_preserves_same_url_on_other_adapter_site_and_host(self):
        app=Publications();app.generations['other.test/race']='A'
        with proxy('ultracache',app,other_profile='ultracache') as get:
            other={'Host':'other.test','Accept':'text/html'}
            other_token='d'*64 if 'X-WV-Gateway' in get.request_headers else 'C'*32
            self.assertEqual(control(get,enabled=True,names='',extra={'Host':'other.test','X-UltraCache-Token':other_token})[0],200)
            self.assertEqual(get('/race',extra=other)[0],200)
            self.primed(get,app)
            self.assertEqual(get('/race',extra={'Accept':'text/html'})[0],200)
            status,fields,body=get('/race',extra=other)
            self.assertEqual((status,cache(fields)),(200,'HIT'));self.assertIn('A[',body)


if __name__=='__main__':unittest.main()
