"""Trusted adapter: register model requests as jobs; fence reads and responses.

No user paths/DSNs or live collection. Legacy reads require administrative mapping.
"""
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'persistence'))
import P01_Workspace_Model as model
import P01_Workspace_Legacy as legacy
import P01_Workspace_Legacy_Readiness as legacy_readiness
import P01_Workspace_Legacy_Jobs as legacy_jobs
import P01_Workspace_Live_Intent as live_intent
import P01_Workspace_Category_Reader as category_reader
import P01_Workspace_Observed_Signals as observed_signals
import P01_Workspace_Signal_Summary as signal_summary
import P01_Workspace_Signal_Quality as signal_quality
import P01_Workspace_Observation_Comparison as observation_comparison
import P01_Workspace_Category_Signal_Coverage as category_signal_coverage

runtime,ws,pg=model.runtime,model.ws,model.pg
VERSION='0.6.25'
BUNDLE=re.compile(r'bnd-[0-9a-f]{20}')


class SourceRoots:
    """Trusted server configuration, disjoint physical stores for each workspace."""
    def __init__(self,roots):
        pg.require(type(roots) is dict and len(roots)<=1024,'model_input_invalid')
        self._roots={}
        for workspace_id,value in roots.items():
            ws.identifier(workspace_id)
            pg.require(isinstance(value,(str,Path)) and '\x00' not in str(value),'model_input_invalid')
            path=Path(value).expanduser().absolute()
            pg.require(path==path.resolve() and path.is_dir(),'model_input_invalid')
            pg.require(all(path!=other and path not in other.parents and other not in path.parents
                           for other in self._roots.values()),'model_input_invalid')
            self._roots[workspace_id]=path

    def prepare(self,workspace_id,assessment_id,bundle_id):
        ws.identifier(workspace_id);ws.identifier(assessment_id)
        pg.require(isinstance(bundle_id,str) and BUNDLE.fullmatch(bundle_id),'model_input_invalid')
        root=self._roots.get(workspace_id)
        pg.require(root is not None,'workspace_access_denied')
        projection=model.prepare_source(root,root/'assessments'/assessment_id/'imports'/bundle_id)
        pg.require(projection['import']['assessment_id']==assessment_id and projection['import']['bundle_id']==bundle_id,'identity_mismatch')
        return projection


class WorkspaceService:
    def __init__(self,coordinator,source_roots,legacy_roots=None,legacy_runs=None,approved_scan_scopes=None):
        pg.require(isinstance(coordinator,runtime.Coordinator) and isinstance(source_roots,SourceRoots),'model_input_invalid')
        self.coordinator,self.sources=coordinator,source_roots
        pg.require(legacy_roots is None or isinstance(legacy_roots,LegacySources),'model_input_invalid')
        self.legacy_sources=legacy_roots or LegacySources({})
        pg.require(legacy_runs is None or isinstance(legacy_runs,legacy_jobs.LegacyRunRoots),'workspace_input_invalid')
        self.legacy_runs=legacy_runs or legacy_jobs.LegacyRunRoots({})
        pg.require(approved_scan_scopes is None or isinstance(approved_scan_scopes,live_intent.ApprovedScopes),'workspace_input_invalid')
        self.approved_scan_scopes=approved_scan_scopes or live_intent.ApprovedScopes({})

    def registry(self,actor,*,after='',limit=100):
        pg.require(runtime.connection_target(actor)==self.coordinator.lease.target,'workspace_connection_mismatch')
        registry=ws.list_workspaces(actor,after,limit)
        # Global lifecycle metadata contains no inventory/private active ID.
        # An ID is shown only if this actor has the actual workspace grant.
        c=self.coordinator
        with c._condition:
            c._live();visible=None
            if c.workspace_id is not None:
                try:runtime.authorize(actor,c.workspace_id,'workspace:read',c.lease.target);visible=c.workspace_id
                except pg.PersistenceError as exc:
                    if str(exc)!='workspace_access_denied':raise
            return dict(registry,lifecycle=dict(state=c.state,generation=c.generation,workspace_id=visible))

    def active_token(self,actor,workspace_id,generation):
        ws.identifier(workspace_id);runtime.require_generation(generation)
        pg.require(runtime.connection_target(actor)==self.coordinator.lease.target,'workspace_connection_mismatch')
        snapshot=self.coordinator.snapshot(actor)
        pg.require(snapshot['state']=='open' and snapshot['workspace_id']==workspace_id
                   and snapshot['generation']==generation,'workspace_generation_stale')
        return runtime.Token(workspace_id,generation,self.coordinator.lease.lease_id)

    def _call(self,actor,token,permission,function,*args,**kwargs):
        with self.coordinator.borrow(actor,token,permission) as operation:
            operation.check()
            result=function(actor,token.workspace_id,token,*args,**kwargs)
            operation.check()
            return dict(result,workspace_id=token.workspace_id,generation=token.generation)

    def objects(self,actor,token,**query):
        return self._call(actor,token,'workspace:read',model.list_objects,**query)
    def categories(self,actor,token,**query):
        return self._call(actor,token,'workspace:read',category_reader.inventory,**query)
    def category_coverage(self,actor,token,**query):
        return self._call(actor,token,'workspace:read',category_reader.coverage,**query)
    def category_signal_coverage(self,actor,token,**query):
        return self._call(actor,token,'workspace:read',category_signal_coverage.overview,**query)
    def observation_comparison(self,actor,token,object_id,**query):
        return self._call(actor,token,'workspace:read',observation_comparison.object_comparison,object_id,**query)
    def signal_quality(self,actor,token,object_id,**query):
        return self._call(actor,token,'workspace:read',signal_quality.object_quality,object_id,**query)
    def signal_summary(self,actor,token,object_id,**query):
        return self._call(actor,token,'workspace:read',signal_summary.object_summary,object_id,**query)
    def observed_signals(self,actor,token,object_id,**query):
        return self._call(actor,token,'workspace:read',observed_signals.object_signals,object_id,**query)
    def object(self,actor,token,object_id,**query):
        return self._call(actor,token,'workspace:read',model.object_state,object_id,**query)
    def graph(self,actor,token,root_id,**query):
        return self._call(actor,token,'workspace:read',model.graph,root_id,**query)
    def declare_object(self,actor,token,*args,**fields):
        return self._call(actor,token,'workspace:write',model.declare_object,*args,**fields)
    def declare_attribute(self,actor,token,*args,**fields):
        return self._call(actor,token,'workspace:write',model.declare_attribute,*args,**fields)
    def relationship(self,actor,token,*args,**fields):
        return self._call(actor,token,'workspace:write',model.relationship,*args,**fields)
    def apply_import(self,actor,token,plan_id,request_id):
        return self._call(actor,token,'workspace:write',model.apply_import,plan_id,request_id)
    def preview_import(self,actor,token,assessment_id,bundle_id,**selection):
        with self.coordinator.borrow(actor,token,'workspace:write') as operation:
            projection=self.sources.prepare(token.workspace_id,assessment_id,bundle_id)
            operation.check()
            result=model.preview_import(actor,token.workspace_id,token,projection,**selection)
            operation.check()
            return dict(result,generation=token.generation)

    def live_scan_intent(self,actor,token,scope_id,mode,*,ack_authorized_access=False):
        # Preview only. No scanner, network API, credentials, or persistent job.
        with self.coordinator.borrow(actor,token,'workspace:write') as operation:
            result=live_intent.preview(operation,self.approved_scan_scopes,scope_id,mode,
                                       ack_authorized_access=ack_authorized_access)
            operation.check()
            return result

    def legacy_checkpoint(self,actor,token,*,timeout=10):
        # Only the trusted, offline status command is allowed in v0.6.39.
        with self.coordinator.borrow(actor,token,'workspace:read') as operation:
            operation.check()
            root=self.legacy_runs.get(token.workspace_id)
            operation.check()
            result=legacy_jobs.checkpoint(operation,root,timeout=timeout)
            operation.check()
            return dict(result,workspace_id=token.workspace_id,generation=token.generation)

    def legacy_readiness(self,actor,token,bundle_id,*,expected_revision=None):
        # SQL mapping/authorization MUST precede any original-store I/O.
        with self.coordinator.borrow(actor,token,'workspace:read') as operation:
            snapshot=legacy.source_snapshot(actor,token.workspace_id,token,bundle_id)
            operation.check()
            projection=self.legacy_sources.prepare(snapshot['import']['assessment_id'],bundle_id)
            operation.check()
            result=legacy_readiness.inspect(actor,token.workspace_id,token,snapshot,projection,
                                             expected_revision=expected_revision)
            operation.check()
            return dict(result,generation=token.generation)

    def preview_legacy(self,actor,token,bundle_id,**selection):
        with self.coordinator.borrow(actor,token,'workspace:write') as operation:
            snapshot=legacy.source_snapshot(actor,token.workspace_id,token,bundle_id)
            projection=self.legacy_sources.prepare(snapshot['import']['assessment_id'],bundle_id)
            operation.check()
            result=legacy.preview(actor,token.workspace_id,token,projection,snapshot,**selection)
            operation.check();return dict(result,generation=token.generation)

    def apply_legacy(self,actor,token,plan_id,request_id):
        with self.coordinator.borrow(actor,token,'workspace:write') as operation:
            replay=legacy.replay_request(actor,token.workspace_id,token,plan_id,request_id)
            if replay:operation.check();return dict(replay,generation=token.generation)
            payload=legacy.read_plan(actor,token.workspace_id,token,plan_id)
            imported=payload['source']['import']
            projection=self.legacy_sources.prepare(imported['assessment_id'],imported['bundle_id'])
            operation.check()
            result=legacy.apply(actor,token.workspace_id,token,plan_id,request_id,projection)
            operation.check();return dict(result,generation=token.generation)

    def legacy_report(self,actor,token,collection_id,**query):
        return self._call(actor,token,'workspace:read',legacy.report,collection_id,**query)


class LegacySources:
    """Read-only original stores keyed by assessment; SQL mapping precedes access.

    Shared stores are permitted only here. IDs select a fixed assessment directory,
    never a client path, and verified receipts bind the returned original identity.
    """
    def __init__(self,roots):
        pg.require(type(roots) is dict and len(roots)<=1024,'model_input_invalid')
        self._roots={}
        for assessment_id,value in roots.items():
            ws.identifier(assessment_id)
            pg.require(isinstance(value,(str,Path)) and '\x00' not in str(value),'model_input_invalid')
            path=Path(value).expanduser().absolute()
            pg.require(path==path.resolve() and path.is_dir(),'model_input_invalid')
            self._roots[assessment_id]=path
    def prepare(self,assessment_id,bundle_id):
        ws.identifier(assessment_id)
        pg.require(isinstance(bundle_id,str) and BUNDLE.fullmatch(bundle_id),'model_input_invalid')
        root=self._roots.get(assessment_id);pg.require(root is not None,'legacy_source_unavailable')
        projection=model.prepare_source(root,root/'assessments'/assessment_id/'imports'/bundle_id)
        pg.require(projection['import']['assessment_id']==assessment_id and projection['import']['bundle_id']==bundle_id,'identity_mismatch')
        return projection
