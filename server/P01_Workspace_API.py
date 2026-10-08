#!/usr/bin/env python3
"""Separate opt-in human workspace API; explicit SQL identity and generation."""
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
from types import MappingProxyType
from urllib.parse import parse_qsl
sys.path.insert(0,str(Path(__file__).resolve().parent))
import P01_Operator_API as http
import P01_Operator_Auth as authn
import P01_Operator_Web as web
import P01_Workspace_Service as backend
import P01_Workspace_Audit as workspace_audit
import P01_Workspace_Category_Reader as category_reader
pg,ws,runtime,model=backend.pg,backend.ws,backend.runtime,backend.model
VERSION='0.6.30'
MAX_BODY=128*1024
BASE='/api/v1/workspaces'
ROUTE=re.compile(BASE+r'/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/(open|close|categories/(?:compute|network|services|components)|objects|objects/([A-Za-z0-9][A-Za-z0-9._-]{0,127})|graph/([A-Za-z0-9][A-Za-z0-9._-]{0,127})|declarations|relationships|imports/preview|imports/apply|legacy/preview|legacy/apply|legacy/(bnd-[0-9a-f]{20})/report)')

class BindingPolicy:
    """Immutable server configuration, never request-supplied role or path."""
    __slots__=('roles','coordinator_role','sources','legacy_sources')
    def __init__(self,raw,accounts):
        try:
            if not isinstance(raw,bytes) or not 1<=len(raw)<=256*1024:raise ValueError()
            doc=json.loads(raw.decode('utf-8'),object_pairs_hook=authn.unique_object)
            required={'binding_version','coordinator_role','bindings','sources'}
            if type(doc) is not dict or not required<=set(doc) or set(doc)-required-{'legacy_sources'} or doc['binding_version']!='1':raise ValueError()
            role=ws.identifier(doc['coordinator_role']);rows=doc['bindings']
            if type(rows) is not list or not 1<=len(rows)<=1024:raise ValueError()
            operators={a.operator_id for a in accounts.accounts.values()};roles={};used={role}
            for row in rows:
                if type(row) is not dict or set(row)!={'operator_id','db_role'}:raise ValueError()
                operator=authn.identifier(row['operator_id']);db_role=ws.identifier(row['db_role'])
                if operator not in operators or operator in roles or db_role in used:raise ValueError()
                roles[operator]=db_role;used.add(db_role)
            sources=backend.SourceRoots(doc['sources'])
            object.__setattr__(self,'roles',MappingProxyType(roles))
            object.__setattr__(self,'coordinator_role',role);object.__setattr__(self,'sources',sources)
            object.__setattr__(self,'legacy_sources',backend.LegacySources(doc.get('legacy_sources',{})))
        except (ValueError,TypeError,UnicodeError,RecursionError,KeyError,OSError,pg.PersistenceError):
            raise ValueError('invalid workspace binding policy') from None
    def __setattr__(self,key,value):raise AttributeError('workspace bindings are immutable')
    def __delattr__(self,key):raise AttributeError('workspace bindings are immutable')

def load_bindings(path,accounts):
    fd=None
    try:
        path=Path(path)
        if path.absolute()!=path.resolve():raise ValueError()
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>256*1024:raise ValueError()
        if os.name=='posix' and (info.st_mode&0o077 or info.st_uid not in (0,os.geteuid())):raise ValueError()
        with os.fdopen(fd,'rb') as stream:
            fd=None;return BindingPolicy(stream.read(256*1024+1),accounts)
    except (ValueError,TypeError,OSError):raise ValueError('invalid workspace binding policy') from None
    finally:
        if fd is not None:os.close(fd)

class RoleConnections:
    """Server-only broker; one fresh connection per operator request."""
    def __init__(self,bindings,connect=pg.open_connection):
        pg.require(isinstance(bindings,BindingPolicy),'workspace_input_invalid')
        self.bindings,self.connect=bindings,connect
    def open(self,role):
        from psycopg import sql
        pg.require(role in set(self.bindings.roles.values())|{self.bindings.coordinator_role},'workspace_access_denied')
        conn=self.connect()
        try:
            unsafe=conn.execute('SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname=current_user').fetchone()
            pg.require(unsafe is not None and not unsafe[0],'workspace_role_invalid')
            conn.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(role)))
            unsafe=conn.execute('SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname=current_user').fetchone()
            pg.require(unsafe is not None and not unsafe[0],'workspace_role_invalid')
            pg.require(conn.execute('SELECT current_user').fetchone()[0]==role,'workspace_role_invalid')
            if role!=self.bindings.coordinator_role:
                forbidden=conn.execute('SELECT EXISTS (SELECT 1 FROM pg_roles WHERE '
                    '(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolname=%s) '
                    "AND pg_has_role(current_user,oid,'MEMBER'))",(self.bindings.coordinator_role,)).fetchone()[0]
                pg.require(not forbidden,'workspace_role_invalid')
            return conn
        except BaseException:conn.close();raise
    @contextmanager
    def actor(self,operator):
        role=self.bindings.roles.get(operator)
        if role is None:raise authn.AccessError('workspace_access_denied',403)
        conn=self.open(role)
        try:yield conn
        finally:conn.close()

class HumanWorkspaceService:
    def __init__(self,auth,connections,workspace):
        pg.require(isinstance(auth,authn.LocalAuth) and isinstance(connections,RoleConnections)
            and isinstance(workspace,backend.WorkspaceService),'workspace_input_invalid')
        self.auth,self.connections,self.workspace=auth,connections,workspace
    def execute(self,bearer,action,workspace_id=None,**fields):
        operator=self.auth.operator_id(bearer)
        with self.connections.actor(operator) as conn:
            self.auth.operator_id(bearer)
            if action=='registry':result=self.workspace.registry(conn,**fields)
            elif action in ('open','close'):
                generation=fields.pop('generation')
                c=self.workspace.coordinator
                if action=='open':
                    token=c.open(conn,workspace_id,generation)
                    result=dict(status='opened',workspace_id=workspace_id,generation=token.generation)
                else:
                    new_generation=c.close(conn,workspace_id,generation,timeout=fields.pop('timeout',5))
                    result=dict(status='closed',workspace_id=workspace_id,generation=new_generation)
            else:
                token=self.workspace.active_token(conn,workspace_id,fields.pop('generation'))
                functions={'objects':self.workspace.objects,'object':self.workspace.object,
                    'graph':self.workspace.graph,'categories':self.workspace.categories,'declare_object':self.workspace.declare_object,
                    'declare_attribute':self.workspace.declare_attribute,'relationship':self.workspace.relationship,
                    'preview_import':self.workspace.preview_import,'apply_import':self.workspace.apply_import}
                functions.update(preview_legacy=self.workspace.preview_legacy,apply_legacy=self.workspace.apply_legacy,
                                 legacy_report=self.workspace.legacy_report)
                pg.require(action in functions,'workspace_input_invalid')
                result=functions[action](conn,token,**fields)
            # Logout/expiry can race a committed mutation; suppress delivery and
            # reconcile its request receipt. Session expiry is not DB rollback.
            self.auth.operator_id(bearer)
            return result

class WorkspaceHandler(http.OperatorHandler):
    server_version='CancaWorkspace/'+VERSION
    _browser_origin=web.WebHandler._browser_origin
    def _json(self):
        length=self._header('Content-Length')
        if self._header('Content-Type')!='application/json' or not length or not re.fullmatch('[1-9][0-9]{0,5}',length):
            raise authn.AccessError('http_request_invalid',400)
        size=int(length)
        if size>MAX_BODY:raise authn.AccessError('http_request_invalid',400)
        raw=self.rfile.read(size)
        if len(raw)!=size:raise authn.AccessError('http_request_invalid',400)
        try:doc=json.loads(raw.decode('utf-8'),object_pairs_hook=authn.unique_object,parse_constant=lambda value:(_ for _ in ()).throw(ValueError()))
        except (ValueError,UnicodeError,RecursionError):raise authn.AccessError('http_request_invalid',400) from None
        if type(doc) is not dict:raise authn.AccessError('http_request_invalid',400)
        return doc
    @staticmethod
    def _fields(doc,required,optional=()):
        if not set(required)<=set(doc) or set(doc)-set(required)-set(optional):raise authn.AccessError('workspace_input_invalid',400)
        return dict(doc)
    def _dispatch(self,method):
        try:
            path=self._path();self._browser_origin()
            if path.path=='/api/v1/operator/session' and method in ('POST','DELETE'):
                if path.query:raise authn.AccessError('http_request_invalid',400)
                if method=='POST':
                    doc=self._fields(self._json(),('username','password'))
                    result=self.server.service.auth.login(**doc)
                    if getattr(self,'_audit_request',None) is not None:self._audit_operator=result['operator_id']
                    self._send(201,result)
                else:
                    self._empty_body();self.server.service.auth.logout(self._bearer());self._send(200,dict(status='logged_out'))
                return
            self._empty_body() if method=='GET' else None
            if method=='GET' and path.path=='/healthz' and not path.query:
                self._send(200,dict(status='ok',version=VERSION,authentication_mode='local_workspace_operator'));return
            bearer=self._bearer();self.server.service.auth.operator_id(bearer)
            if method=='GET' and path.path==BASE:
                fields=self._query(path.query,{'after','limit'});action='registry';workspace_id=None
            else:
                match=ROUTE.fullmatch(path.path)
                if not match:raise authn.AccessError('route_not_found',404)
                workspace_id,route=match[1],match[2]
                if method=='GET' and match[5] is not None:
                    action='legacy_report';fields=self._query(path.query,{'generation','expected_revision','after_ordinal','limit','expected_scope_sha256'})
                    if 'generation' not in fields:raise authn.AccessError('workspace_input_invalid',400)
                    fields['collection_id']=match[5]
                elif method=='GET' and route.startswith('categories/'):
                    action='categories';fields=self._query(path.query,{'generation','expected_revision','max_pages','after','site_id','environment_id','kind','origin'})
                    if 'generation' not in fields:raise authn.AccessError('workspace_input_invalid',400)
                    fields['category']=route.split('/')[1]
                elif method=='GET' and route in ('objects','objects/'+str(match[3]),'graph/'+str(match[4])):
                    allowed={'generation','expected_revision'}
                    if route=='objects':allowed|={'after','limit'};action='objects'
                    elif route.startswith('objects/'):action='object'
                    else:allowed|={'depth','node_limit','edge_limit'};action='graph'
                    fields=self._query(path.query,allowed)
                    if 'generation' not in fields:raise authn.AccessError('workspace_input_invalid',400)
                    if action=='object':fields['object_id']=match[3]
                    if action=='graph':fields['root_id']=match[4]
                elif method=='POST' and not path.query:
                    doc=self._json()
                    if route in ('open','close'):
                        action=route;fields=self._fields(doc,('generation',),('timeout',) if route=='close' else ())
                    elif route=='objects':
                        action='declare_object';fields=self._fields(doc,('generation','expected_revision','request_id','object_id','kind','label','reason'),('attributes','site_id','environment_id'))
                    elif route=='declarations':
                        action='declare_attribute';fields=self._fields(doc,('generation','expected_revision','request_id','object_id','name','value','reason'))
                    elif route=='relationships':
                        action='relationship';fields=self._fields(doc,('generation','expected_revision','request_id','relationship_id','source_id','target_id','kind','reason'),('active',))
                    elif route=='imports/preview':
                        action='preview_import';fields=self._fields(doc,('generation','assessment_id','bundle_id'),('mode','categories','decisions','site_id','environment_id'))
                        if 'decisions' in fields:
                            decisions=fields['decisions']
                            if type(decisions) is not dict or len(decisions)>1000 or any(not re.fullmatch('0|[1-9][0-9]{0,2}',k) for k in decisions):raise authn.AccessError('workspace_input_invalid',400)
                            fields['decisions']={int(k):v for k,v in decisions.items()}
                    elif route=='imports/apply':
                        action='apply_import';fields=self._fields(doc,('generation','plan_id','request_id'))
                    elif route=='legacy/preview':
                        action='preview_legacy';fields=self._fields(doc,('generation','bundle_id'),('mode','categories','decisions','site_id','environment_id'))
                        if 'decisions' in fields:
                            decisions=fields['decisions']
                            if type(decisions) is not dict or len(decisions)>1000 or any(not re.fullmatch('0|[1-9][0-9]{0,2}',k) for k in decisions):raise authn.AccessError('workspace_input_invalid',400)
                            fields['decisions']={int(k):v for k,v in decisions.items()}
                    elif route=='legacy/apply':
                        action='apply_legacy';fields=self._fields(doc,('generation','plan_id','request_id'))
                    else:raise authn.AccessError('route_not_found',404)
                else:raise authn.AccessError('route_not_found',404)
            self._validate(action,fields)
            result=self.server.service.execute(bearer,action,workspace_id,**fields)
            if getattr(self,'_audit_request',None) is not None and workspace_id is not None:
                self._audit_workspace=workspace_id
            self._send(200,result)
        except authn.AccessError as exc:self._send(exc.status,dict(status='failed',error_code=str(exc)))
        except pg.PersistenceError as exc:
            code=str(exc) if str(exc) in backend.legacy.ERRORS else 'database_failed'
            status=403 if code=='workspace_access_denied' else 400 if code in ('model_input_invalid','workspace_input_invalid') else 404 if code in ('model_object_not_found','model_plan_not_found') else 409 if code in ('model_revision_stale','workspace_generation_stale','workspace_runtime_busy','workspace_close_pending','model_request_conflict','model_review_required','model_import_conflict','model_relationship_conflict') else 503
            if code in ('legacy_source_unavailable','legacy_plan_not_found','legacy_report_not_found'):status=404
            if code in ('legacy_source_conflict','legacy_scope_conflict'):status=409
            self._send(status,dict(status='failed',error_code=code))
        except Exception:self._send(503,dict(status='failed',error_code='workspace_request_failed'))
    def _serve(self,method):
        sink=self.server.audit
        if sink is None:
            self._dispatch(method);return
        self._audit_request=None;self._audit_operator=None;self._audit_workspace=None
        self._audit_http_status=None;self._audit_delivery_failed=False
        try:self._audit_request=sink.begin(workspace_audit.operation(method,self.path))
        except workspace_audit.AuditError:
            self._send(503,dict(status='failed',error_code='workspace_audit_unavailable'));return
        outcome='response_written'
        try:
            self._dispatch(method)
            if self._audit_delivery_failed:outcome='delivery_failed'
            elif self._audit_http_status is None:outcome='handler_failed'
        except (BrokenPipeError,ConnectionResetError,TimeoutError):
            outcome='delivery_failed';self.close_connection=True
        except Exception:
            outcome='handler_failed';self.close_connection=True
        finally:
            try:sink.finish(self._audit_request,http_status=self._audit_http_status,outcome=outcome,
                            operator_id=self._audit_operator,workspace_id=self._audit_workspace)
            except workspace_audit.AuditError:self.close_connection=True

    @staticmethod
    def _validate(action,fields):
        for key in ('generation','expected_revision'):
            if key in fields:runtime.require_generation(fields[key])
        if action in ('registry','objects'):ws.page_args(fields.get('after',''),fields.get('limit',100))
        if action=='categories':
            model.require(fields.get('category') in category_reader.CATEGORY_KINDS)
            for location in ('site_id','environment_id'):
                if location in fields:ws.identifier(fields[location])
            if 'kind' in fields:model.require(fields['kind'] in category_reader.CATEGORY_KINDS[fields['category']])
            if 'origin' in fields:model.require(fields['origin'] in ('declared','observed'))
            if fields.get('after'):model.require('expected_revision' in fields)
            model.require(type(fields.get('max_pages',category_reader.MAX_PAGES)) is int and 1<=fields.get('max_pages',category_reader.MAX_PAGES)<=category_reader.MAX_PAGES)
        if action=='close':runtime.Coordinator._deadline(fields.get('timeout',5))
        if action=='graph':
            for key,low,high in (('depth',0,4),('node_limit',1,100),('edge_limit',1,200)):
                value=fields.get(key,{'depth':2,'node_limit':100,'edge_limit':200}[key])
                model.require(type(value) is int and low<=value<=high)
        if action in ('preview_import','preview_legacy'):
            model.require(fields.get('mode','merge') in ('merge','evidence_only'))
            model.require(type(fields.get('categories',['identity'])) is list and fields.get('categories',['identity'])==['identity'])
            if action=='preview_import':ws.identifier(fields['assessment_id'])
            model.require(isinstance(fields['bundle_id'],str) and backend.BUNDLE.fullmatch(fields['bundle_id']))
    @staticmethod
    def _query(raw,allowed):
        try:
            pairs=parse_qsl(raw,keep_blank_values=True,strict_parsing=True,max_num_fields=8) if raw else []
            values=dict(pairs)
            if len(values)!=len(pairs) or set(values)-allowed:raise ValueError()
            for key in set(values)-{'after','expected_scope_sha256','site_id','environment_id','kind','origin'}:
                if not re.fullmatch('(-1|0|[1-9][0-9]{0,18})' if key=='after_ordinal' else '0|[1-9][0-9]{0,18}',values[key]):raise ValueError()
                values[key]=int(values[key])
            if 'expected_scope_sha256' in values and not re.fullmatch('[0-9a-f]{64}',values['expected_scope_sha256']):raise ValueError()
            return values
        except ValueError:raise authn.AccessError('workspace_input_invalid',400) from None

class WorkspaceServer(http.OperatorServer):
    def __init__(self,address,service):
        super().__init__(address,service);self.RequestHandlerClass=WorkspaceHandler;self._owns_coordinator=False
    def server_close(self):
        try:super().server_close()
        finally:
            if self._owns_coordinator:self.service.workspace.coordinator.shutdown(timeout=30)

def create_server(accounts_path,bindings_path,host='127.0.0.1',port=8879,*,tls_cert=None,tls_key=None,audit_path=None):
    if type(port) is not int or not 0<=port<=65535:raise ValueError('invalid workspace port')
    address=ipaddress.ip_address(host);tls=bool(tls_cert and tls_key)
    if address.version!=4 or bool(tls_cert)!=bool(tls_key) or (not tls and str(address)!='127.0.0.1'):raise ValueError('remote workspace API requires TLS')
    context=None
    if tls:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(tls_cert,tls_key)
    accounts=authn.load_policy(accounts_path);bindings=load_bindings(bindings_path,accounts)
    connections=RoleConnections(bindings);control=connections.open(bindings.coordinator_role)
    try:pg.schema_check(control,minimum=9,legacy=True)
    except BaseException:control.close();raise
    coordinator=runtime.Coordinator(runtime.SessionLease(control));server=None
    try:
        coordinator.start()
        service=HumanWorkspaceService(authn.LocalAuth(accounts),connections,backend.WorkspaceService(coordinator,bindings.sources,bindings.legacy_sources))
        server=WorkspaceServer((str(address),port),service);server._owns_coordinator=True
        if audit_path is not None:server.audit=workspace_audit.FileAudit(audit_path)
        if context:server.tls_context=context
        return server
    except BaseException:
        if server is not None:server.server_close()
        try:coordinator.shutdown(timeout=0)
        finally:control.close()
        raise

def cli(argv=None):
    parser=argparse.ArgumentParser(description='Cancã opt-in workspace API '+VERSION)
    parser.add_argument('--accounts',required=True);parser.add_argument('--bindings',required=True)
    parser.add_argument('--host',default='127.0.0.1');parser.add_argument('--port',type=int,default=8879)
    parser.add_argument('--tls-cert');parser.add_argument('--tls-key');parser.add_argument('--audit-file');args=parser.parse_args(argv)
    server=None
    try:
        server=create_server(args.accounts,args.bindings,args.host,args.port,tls_cert=args.tls_cert,tls_key=args.tls_key,audit_path=args.audit_file)
        print(json.dumps(dict(status='listening',version=VERSION)),flush=True);server.serve_forever();return 0
    except KeyboardInterrupt:return 0
    except workspace_audit.AuditError:
        print(json.dumps(dict(status='failed',error_code='workspace_audit_unavailable')));return 2
    except Exception:
        print(json.dumps(dict(status='failed',error_code='workspace_startup_failed')));return 2
    finally:
        if server is not None:
            try:server.server_close()
            except (pg.PersistenceError,workspace_audit.AuditError):
                print(json.dumps(dict(status='failed',error_code='workspace_shutdown_failed')));return 2


if __name__=='__main__':raise SystemExit(cli())
