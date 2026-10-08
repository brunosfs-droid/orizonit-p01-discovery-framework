"""Human binding and real HTTP framing; SQL identity end-to-end runs opt-in."""
from contextlib import closing
import copy
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
import P01_Workspace_API as api
import test_operator_auth as fixture
import test_workspace_model as models

def bindings(role='canca_ws_writer'):
    return dict(binding_version='1',coordinator_role='canca_ws_coordinator',
        bindings=[dict(operator_id='OP-01',db_role=role)],sources={})

def policy():return api.BindingPolicy(json.dumps(bindings()).encode(),fixture.policy())

class BindingTests(unittest.TestCase):
    def test_bindings_are_distinct_immutable_and_known_accounts_only(self):
        p=policy();self.assertEqual(p.roles['OP-01'],'canca_ws_writer')
        with self.assertRaises(TypeError):p.roles['OP-01']='other'
        with self.assertRaises(AttributeError):p.coordinator_role='other'
        for change in ('duplicate','unknown','coordinator','invalid'):
            doc=bindings()
            if change=='duplicate':doc['bindings'].append(copy.deepcopy(doc['bindings'][0]))
            elif change=='unknown':doc['bindings'][0]['operator_id']='OP-OTHER'
            elif change=='coordinator':doc['bindings'][0]['db_role']=doc['coordinator_role']
            else:doc['bindings'][0]['db_role']='../private'
            with self.assertRaises(ValueError):api.BindingPolicy(json.dumps(doc).encode(),fixture.policy())
    def test_private_file_rejects_symlink_public_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'binding.json';path.write_text(json.dumps(bindings()));path.chmod(0o600)
            self.assertEqual(api.load_bindings(path,fixture.policy()).roles,policy().roles)
            alias=Path(temp)/'alias';alias.symlink_to(path)
            with self.assertRaises(ValueError):api.load_bindings(alias,fixture.policy())
            if os.name=='posix':
                path.chmod(0o644)
                with self.assertRaises(ValueError):api.load_bindings(path,fixture.policy())
            with self.assertRaises(ValueError):api.BindingPolicy(b'{"binding_version":"1","binding_version":"1"}',fixture.policy())
    def test_remote_plaintext_invalid_config_do_not_connect_or_listen(self):
        with patch.object(api,'RoleConnections') as connections,patch.object(api,'WorkspaceServer') as listener:
            for host in ('0.0.0.0','192.0.2.1','::1','localhost'):
                with self.assertRaises(ValueError):api.create_server('absent','absent',host,0)
            with self.assertRaises(ValueError):api.create_server('absent','absent',port=0)
            connections.assert_not_called();listener.assert_not_called()
    def test_startup_failure_and_server_close_release_owned_coordinator(self):
        accounts=fixture.policy();config=policy();control=Mock();coordinator=Mock()
        with patch.object(api.authn,'load_policy',return_value=accounts),patch.object(api,'load_bindings',return_value=config),\
             patch.object(api.RoleConnections,'open',return_value=control),patch.object(api.pg,'schema_check'),\
             patch.object(api.runtime,'Coordinator',return_value=coordinator),patch.object(api.runtime,'SessionLease'),\
             patch.object(api,'WorkspaceServer',side_effect=OSError('PRIVATE')),patch.object(api.backend,'WorkspaceService'),\
             patch.object(api,'HumanWorkspaceService'):
            with self.assertRaises(OSError):api.create_server('accounts','bindings',port=0)
            coordinator.shutdown.assert_called_once_with(timeout=0);control.close.assert_called_once()
        backend=Mock();server=api.WorkspaceServer(('127.0.0.1',0),backend);server._owns_coordinator=True
        server.server_close();backend.workspace.coordinator.shutdown.assert_called_once_with(timeout=30)
    def test_schema6_rejected_before_coordinator_or_listener_creation(self):
        control=Mock()
        with patch.object(api.authn,'load_policy',return_value=fixture.policy()),patch.object(api,'load_bindings',return_value=policy()),\
             patch.object(api.RoleConnections,'open',return_value=control),\
             patch.object(api.pg,'schema_check',side_effect=api.pg.PersistenceError('schema_required')),\
             patch.object(api.runtime,'Coordinator') as coordinator,patch.object(api,'WorkspaceServer') as server:
            with self.assertRaisesRegex(api.pg.PersistenceError,'schema_required'):api.create_server('accounts','bindings',port=0)
            coordinator.assert_not_called();server.assert_not_called();control.close.assert_called_once()
    def test_unbound_session_is_denied_before_sql_connection(self):
        doc=fixture.document();doc['accounts'].append(dict(doc['accounts'][0],operator_id='OP-02',username='other'))
        accounts=fixture.policy(doc);config=api.BindingPolicy(json.dumps(bindings()).encode(),accounts)
        auth=api.authn.LocalAuth(accounts);bearer=auth.login('other',fixture.PASSWORD)['access_token']
        connect=Mock();service=api.HumanWorkspaceService(auth,api.RoleConnections(config,connect),Mock(spec=api.backend.WorkspaceService))
        with self.assertRaisesRegex(api.authn.AccessError,'workspace_access_denied'):service.execute(bearer,'registry')
        connect.assert_not_called()
    def test_session_logout_during_work_suppresses_delivery_and_closes_connection(self):
        auth=api.authn.LocalAuth(fixture.policy());bearer=auth.login('reader',fixture.PASSWORD)['access_token']
        conn=Mock();connections=api.RoleConnections(policy(),connect=lambda:conn)
        backend=Mock(spec=api.backend.WorkspaceService)
        # Trusted collaborators only; avoid SQL in this session race test.
        from contextlib import contextmanager
        @contextmanager
        def actor(operator):
            self.assertEqual(operator,'OP-01')
            try:yield conn
            finally:conn.close()
        connections.actor=actor
        backend.registry.side_effect=lambda *a,**kw:(auth.logout(bearer) or {'private':'payload'})
        service=api.HumanWorkspaceService(auth,connections,backend)
        with self.assertRaisesRegex(api.authn.AccessError,'authentication_required'):service.execute(bearer,'registry')
        conn.close.assert_called_once()

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.auth=api.authn.LocalAuth(fixture.policy())
        self.service=Mock();self.service.auth=self.auth;self.service.execute.return_value={'status':'ok'}
        self.server=api.WorkspaceServer(('127.0.0.1',0),self.service)
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start();self.addCleanup(self.stop)
    def stop(self):self.server.shutdown();self.server.server_close();self.worker.join(5)
    def request(self,method,path,payload=None,headers=None):
        with closing(http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)) as conn:
            conn.request(method,path,json.dumps(payload) if payload is not None else None,headers or {})
            response=conn.getresponse();raw=response.read()
            self.assertEqual(response.getheader('Cache-Control'),'no-store')
            self.assertIsNone(response.getheader('Set-Cookie'));self.assertIsNone(response.getheader('Access-Control-Allow-Origin'))
            return response.status,json.loads(raw)
    def login(self):
        code,doc=self.request('POST','/api/v1/operator/session',dict(username='reader',password=fixture.PASSWORD),{'Content-Type':'application/json'})
        self.assertEqual(code,201);return {'Authorization':'Bearer '+doc['access_token'],'Content-Type':'application/json'}
    def test_login_registry_open_read_close_logout(self):
        self.assertEqual(self.request('GET','/healthz')[0],200);headers=self.login()
        for method,path,payload,action in (
            ('GET',api.BASE,None,'registry'),('POST',api.BASE+'/A/open',{'generation':1},'open'),
            ('GET',api.BASE+'/A/objects?generation=2&expected_revision=0',None,'objects'),
            ('GET',api.BASE+'/A/objects/server?generation=2',None,'object'),
            ('GET',api.BASE+'/A/graph/server?generation=2&depth=0',None,'graph'),
            ('POST',api.BASE+'/A/close',{'generation':2,'timeout':0},'close')):
            self.assertEqual(self.request(method,path,payload,headers)[0],200)
            self.assertEqual(self.service.execute.call_args.args[1],action)
        self.assertEqual(self.request('DELETE','/api/v1/operator/session',headers=headers)[0],200)
        self.service.execute.reset_mock();self.assertEqual(self.request('GET',api.BASE,headers=headers)[0],401);self.service.execute.assert_not_called()
    def test_recorded_observation_comparison_http_contract(self):
        headers=self.login()
        uri=api.BASE+'/A/objects/host-1/signals/comparison?generation=2&expected_revision=7'
        self.assertEqual(self.request('GET',uri,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.args[1],'observation_comparison')
        self.assertEqual(self.service.execute.call_args.kwargs,
                         {'generation':2,'expected_revision':7,'object_id':'host-1'})
        self.service.execute.reset_mock()
        for bad in ('&after=1','&limit=10','&secret=yes','&generation=3'):
            self.assertEqual(self.request('GET',uri+bad,headers=headers)[0],400)
        self.service.execute.assert_not_called()

    def test_signal_quality_http_contract(self):
        headers=self.login()
        uri=api.BASE+'/A/objects/host-1/signals/quality?generation=2&expected_revision=7'
        self.assertEqual(self.request('GET',uri,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.args[1],'signal_quality')
        self.assertEqual(self.service.execute.call_args.kwargs,
                         {'generation':2,'expected_revision':7,'object_id':'host-1'})
        self.service.execute.reset_mock()
        for bad in ('&after=1','&limit=10','&secret=yes','&generation=3'):
            self.assertEqual(self.request('GET',uri+bad,headers=headers)[0],400)
        self.service.execute.assert_not_called()

    def test_observed_signal_summary_http_contract(self):
        headers=self.login()
        uri=api.BASE+'/A/objects/host-1/signals/summary?generation=2&expected_revision=7'
        self.assertEqual(self.request('GET',uri,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.args[1],'signal_summary')
        self.assertEqual(self.service.execute.call_args.kwargs,
                         {'generation':2,'expected_revision':7,'object_id':'host-1'})
        self.service.execute.reset_mock()
        for invalid in ('&after=1','&limit=10','&secret=anything','&generation=3'):
            self.assertEqual(self.request('GET',uri+invalid,headers=headers)[0],400)
        self.service.execute.assert_not_called()

    def test_observed_signals_http_route_requires_fenced_continuation(self):
        headers=self.login()
        path=api.BASE+'/A/objects/host-1/signals?generation=2&expected_revision=3&after=1&limit=1'
        self.assertEqual(self.request('GET',path,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.args[1],'observed_signals')
        self.assertEqual(self.service.execute.call_args.kwargs,
                         {'generation':2,'expected_revision':3,'after':1,'limit':1,'object_id':'host-1'})
        self.service.execute.reset_mock()
        for bad in (
            api.BASE+'/A/objects/host-1/signals?generation=2&after=1',
            api.BASE+'/A/objects/host-1/signals?generation=2&limit=51',
            api.BASE+'/A/objects/host-1/signals?generation=2&after=-1',
            api.BASE+'/A/objects/host-1/signals?generation=2&after=1&after=1',
            api.BASE+'/A/objects/host-1/signals?generation=2&source_refs=secret',
            api.BASE+'/A/objects/host-1/signals?generation=2&limit=0',
        ):
            self.assertIn(self.request('GET',bad,headers=headers)[0],(400,404))
        self.service.execute.assert_not_called()

    def test_category_route_requires_valid_context_and_fixed_category(self):
        headers=self.login()
        path=api.BASE+'/A/categories/network?generation=2&expected_revision=3&max_pages=1'
        self.assertEqual(self.request('GET',path,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.args[1],'categories')
        self.assertEqual(self.service.execute.call_args.kwargs,
                         {'generation':2,'expected_revision':3,'max_pages':1,'category':'network'})
        self.service.execute.reset_mock()
        for bad in (api.BASE+'/A/categories/network',
                    api.BASE+'/A/categories/network?generation=2&max_pages=11',
                    api.BASE+'/A/categories/network?generation=2&max_pages=0',
                    api.BASE+'/A/categories/network?generation=2&token=private',
                    api.BASE+'/A/categories/unknown?generation=2'):
            self.assertIn(self.request('GET',bad,headers=headers)[0],(400,404))
        self.service.execute.assert_not_called()
        resumed=api.BASE+'/A/categories/network?generation=2&expected_revision=3&after=k'
        self.assertEqual(self.request('GET',resumed,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.kwargs['after'],'k')
        self.service.execute.reset_mock()
        self.assertEqual(self.request('GET',api.BASE+'/A/categories/network?generation=2&after=k',headers=headers)[0],400)
        self.service.execute.assert_not_called()

    def test_category_filters_are_whitelisted_and_preserved(self):
        headers=self.login()
        uri=api.BASE+'/A/categories/compute?generation=2&site_id=S1&environment_id=E1'
        self.assertEqual(self.request('GET',uri,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.kwargs['site_id'],'S1')
        self.assertEqual(self.service.execute.call_args.kwargs['environment_id'],'E1')
        self.service.execute.reset_mock()
        for bad in ('site_id=..%2FB','environment_id=has%20space','password=secret'):
            self.assertEqual(self.request('GET',api.BASE+'/A/categories/compute?generation=2&'+bad,headers=headers)[0],400)
        self.service.execute.assert_not_called()

    def test_category_kind_origin_filters_are_strict(self):
        headers=self.login()
        uri=api.BASE+'/A/categories/network?generation=2&kind=vlan&origin=observed'
        self.assertEqual(self.request('GET',uri,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.kwargs['kind'],'vlan')
        self.assertEqual(self.service.execute.call_args.kwargs['origin'],'observed')
        self.service.execute.reset_mock()
        for bad in ('kind=host','origin=manual','kind=vlan&kind=device'):
            self.assertEqual(self.request('GET',api.BASE+'/A/categories/network?generation=2&'+bad,headers=headers)[0],400)
        self.service.execute.assert_not_called()

    def test_category_coverage_route_is_read_only_and_strict(self):
        headers=self.login()
        uri=api.BASE+'/A/categories/network/coverage?generation=2&max_pages=1'
        self.assertEqual(self.request('GET',uri,headers=headers)[0],200)
        self.assertEqual(self.service.execute.call_args.args[1],'category_coverage')
        self.assertEqual(self.service.execute.call_args.kwargs['category'],'network')
        self.service.execute.reset_mock()
        self.assertEqual(self.request('GET',api.BASE+'/A/categories/network/coverage',headers=headers)[0],400)
        self.assertEqual(self.request('GET',uri+'&secret=x',headers=headers)[0],400)
        self.service.execute.assert_not_called()

    def test_missing_forged_query_token_and_node_identity_denied(self):
        for path,headers in ((api.BASE,None),(api.BASE,{'Authorization':'Bearer '+'x'*43}),
                             (api.BASE,{'X-P01-Node-ID':'OP-01'}),(api.BASE+'?access_token=PRIVATE',None)):
            self.assertEqual(self.request('GET',path,headers=headers)[0],401)
        self.service.execute.assert_not_called()
    def test_wrong_host_origin_and_fetch_site_denied(self):
        headers=self.login();self.service.execute.reset_mock()
        for extra,expected in (({'Host':'evil.example:'+str(self.server.server_port)},400),
                               ({'Origin':'https://evil.example'},403),({'Sec-Fetch-Site':'cross-site'},403)):
            self.assertEqual(self.request('GET',api.BASE,headers=dict(headers,**extra))[0],expected)
        self.service.execute.assert_not_called()
    def test_unknown_duplicate_and_missing_context_queries_denied(self):
        headers=self.login()
        for path in (api.BASE+'?limit=1&limit=2',api.BASE+'?db_role=private',
                     api.BASE+'/A/objects',api.BASE+'/A/objects?generation=true',
                     api.BASE+'/A/objects?generation=1&workspace_id=B',
                     api.BASE+'/A/graph/x?generation=1&depth=-1',api.BASE+'/../A/objects?generation=1'):
            self.assertIn(self.request('GET',path,headers=headers)[0],(400,404))
        self.service.execute.assert_not_called()
    def test_manual_routes_preserve_fields_and_reject_role_path_and_lease(self):
        headers=self.login()
        common={'generation':2,'expected_revision':0,'request_id':'request','reason':'LAB'}
        payload=dict(common,object_id='x',kind='host',label='X')
        self.assertEqual(self.request('POST',api.BASE+'/A/objects',payload,headers)[0],200)
        self.assertEqual(self.service.execute.call_args.args[1],'declare_object')
        for field in ('db_role','path','lease_id','workspace_id'):
            self.assertEqual(self.request('POST',api.BASE+'/A/objects',dict(payload,**{field:'PRIVATE'}),headers)[0],400)
        self.assertEqual(self.request('POST',api.BASE+'/A/declarations',dict(common,object_id='x',name='description',value=None),headers)[0],200)
        self.assertEqual(self.request('POST',api.BASE+'/A/relationships',dict(common,relationship_id='edge',source_id='x',target_id='y',kind='depends_on'),headers)[0],200)
    def test_invalid_context_bounds_and_selection_rejected_before_service(self):
        headers=self.login()
        for path,payload in ((api.BASE+'/A/open',{'generation':True}),
                             (api.BASE+'/A/close',{'generation':1,'timeout':31}),
                             (api.BASE+'/A/imports/preview',{'generation':1,'assessment_id':'LAB-001','bundle_id':'bnd-'+'a'*20,'categories':None})):
            self.assertEqual(self.request('POST',path,payload,headers)[0],400)
        for path in (api.BASE+'?limit=101',api.BASE+'/A/graph/x?generation=1&depth=5'):
            self.assertEqual(self.request('GET',path,headers=headers)[0],400)
        self.service.execute.assert_not_called()
    def test_import_handles_and_decision_ordinals_are_strict(self):
        headers=self.login();payload=dict(generation=2,assessment_id='LAB-001',bundle_id='bnd-'+'a'*20,decisions={'0':{'action':'create','reason':'LAB'}})
        self.assertEqual(self.request('POST',api.BASE+'/A/imports/preview',payload,headers)[0],200)
        self.assertIn(0,self.service.execute.call_args.kwargs['decisions'])
        for values in ({'01':{}},{'-1':{}},{'1000':{}},[]):
            self.assertEqual(self.request('POST',api.BASE+'/A/imports/preview',dict(payload,decisions=values),headers)[0],400)
        self.assertEqual(self.request('POST',api.BASE+'/A/imports/apply',dict(generation=2,plan_id='plan',request_id='request'),headers)[0],200)
    def test_backend_fixed_errors_and_redaction(self):
        headers=self.login()
        for error,status in ((api.pg.PersistenceError('workspace_access_denied'),403),
                             (api.pg.PersistenceError('model_revision_stale'),409),
                             (RuntimeError('password=PRIVATE'),503)):
            self.service.execute.side_effect=error
            code,doc=self.request('GET',api.BASE,headers=headers);self.assertEqual(code,status);self.assertNotIn('PRIVATE',json.dumps(doc))
    def test_duplicate_framing_chunked_oversize_and_nonfinite_json_rejected(self):
        headers=self.login()
        for payload in ({'generation':float('nan')},{'generation':1,'padding':'x'*api.MAX_BODY}):
            self.assertEqual(self.request('POST',api.BASE+'/A/open',payload,headers)[0],400)
        for extra in ('Content-Length: 2\r\nContent-Length: 2\r\nContent-Type: application/json\r\n',
                      'Transfer-Encoding: chunked\r\nContent-Type: application/json\r\n'):
            with closing(http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=10)) as conn:
                conn.connect();conn.sock.sendall(('POST /api/v1/operator/session HTTP/1.1\r\nHost: 127.0.0.1:'+str(self.server.server_port)+'\r\n'+extra+'\r\n{}').encode())
                response=http.client.HTTPResponse(conn.sock);response.begin();self.assertEqual(response.status,400);response.read()

@unittest.skipUnless(os.environ.get('CANCA_TEST_WORKSPACE_POSTGRES')=='1','workspace SQL opt-in required')
class APIPostgreSQLTests(unittest.TestCase):
    setUp=models.ModelPostgreSQLTests.setUp
    legacy_rows=models.ModelPostgreSQLTests.legacy_rows
    role=models.ModelPostgreSQLTests.role
    def human(self,role='canca_ws_writer'):
        from psycopg import sql
        self.conn.execute('''DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='canca_ws_broker') THEN
            CREATE ROLE canca_ws_broker NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$''')
        for target in ('canca_ws_writer','canca_ws_a','canca_ws_coordinator'):
            self.conn.execute(sql.SQL('GRANT {} TO canca_ws_broker').format(sql.Identifier(target)))
        config=api.BindingPolicy(json.dumps(bindings(role)).encode(),fixture.policy())
        def connect():
            conn=api.pg.open_connection();conn.execute('SET ROLE canca_ws_broker');return conn
        auth=api.authn.LocalAuth(fixture.policy());bearer=auth.login('reader',fixture.PASSWORD)['access_token']
        service=api.HumanWorkspaceService(auth,api.RoleConnections(config,connect=connect),api.backend.WorkspaceService(self.c,config.sources))
        return service,bearer
    def test_human_identity_mutation_and_reader_denial(self):
        service,bearer=self.human()
        result=service.execute(bearer,'declare_object','A',generation=self.token.generation,expected_revision=0,request_id='human',object_id='host',kind='host',label='Host',reason='LAB')
        self.assertEqual(result['revision'],1)
        self.assertEqual(self.conn.execute('SELECT author_role FROM canca.workspace_objects').fetchone()[0],'canca_ws_writer')
        reader,token=self.human('canca_ws_a')
        self.assertEqual(reader.execute(token,'objects','A',generation=self.token.generation)['objects'][0]['object_id'],'host')
        with self.assertRaisesRegex(api.pg.PersistenceError,'workspace_access_denied'):
            reader.execute(token,'declare_object','A',generation=self.token.generation,expected_revision=1,request_id='denied',object_id='other',kind='host',label='Other',reason='LAB')
    def test_privileged_broker_and_coordinator_member_actor_denied(self):
        service,bearer=self.human()
        service.connections.connect=api.pg.open_connection
        with self.assertRaisesRegex(api.pg.PersistenceError,'workspace_role_invalid'):service.execute(bearer,'registry')
        service,bearer=self.human()
        self.conn.execute('GRANT canca_ws_coordinator TO canca_ws_writer')
        try:
            with self.assertRaisesRegex(api.pg.PersistenceError,'workspace_role_invalid'):service.execute(bearer,'registry')
        finally:self.conn.execute('REVOKE canca_ws_coordinator FROM canca_ws_writer')
    def test_real_http_roles_and_sql_grants(self):
        service,bearer=self.human();server=api.WorkspaceServer(('127.0.0.1',0),service)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            with closing(http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)) as conn:
                conn.request('GET',api.BASE+'/A/objects?generation='+str(self.token.generation),headers={'Authorization':'Bearer '+bearer})
                response=conn.getresponse();self.assertEqual(response.status,200);self.assertEqual(json.loads(response.read())['objects'],[])
            api.ws.revoke_workspace(self.conn,'A','canca_ws_writer','workspace:write')
            with closing(http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)) as conn:
                conn.request('GET',api.BASE+'/A/objects?generation='+str(self.token.generation),headers={'Authorization':'Bearer '+bearer})
                response=conn.getresponse();self.assertEqual(response.status,403);response.read()
        finally:server.shutdown();server.server_close();worker.join(5)
