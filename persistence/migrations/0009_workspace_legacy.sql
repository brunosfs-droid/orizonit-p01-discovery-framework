-- Explicit administrative ownership precedes any legacy read; no inferred backfill.
DO $$ BEGIN
    IF NOT pg_try_advisory_xact_lock(-2660897858987708572::bigint) THEN
        RAISE EXCEPTION 'workspace coordinator is active' USING ERRCODE='55006';
    END IF;
END $$;

-- Application actors never receive raw SELECT on the shared legacy tables.
CREATE FUNCTION canca.workspace_legacy_snapshot(wanted_bundle text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,canca AS $$
DECLARE ws text; i canca.imports; a canca.asset_imports;
    analysis canca.finding_analyses; observations jsonb; evaluations jsonb;
    artifacts jsonb; result jsonb;
BEGIN
    ws := current_setting('canca.workspace_id',true);
    IF NOT canca.workspace_model_allowed(false) THEN
        RAISE EXCEPTION 'workspace context denied' USING ERRCODE='42501';
    END IF;
    SELECT x.* INTO i FROM canca.imports x JOIN canca.workspace_assessments m
        ON m.assessment_id=x.assessment_id AND m.workspace_id=ws
        WHERE x.bundle_id=wanted_bundle;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT * INTO a FROM canca.asset_imports WHERE bundle_id=wanted_bundle;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF a.observation_count>1000 OR i.artifact_count>1024 THEN
        RAISE EXCEPTION 'legacy snapshot bound' USING ERRCODE='54000';
    END IF;
    SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.path),'[]'::jsonb) INTO artifacts
        FROM (SELECT path,role,sha256,size_bytes FROM canca.artifacts
              WHERE bundle_id=wanted_bundle ORDER BY path LIMIT 1025) t;
    SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.ordinal),'[]'::jsonb) INTO observations
        FROM (SELECT ordinal,asset_id,source_asset_id,decision,reason_code,signals,source_refs
              FROM canca.asset_observations WHERE bundle_id=wanted_bundle
              ORDER BY ordinal LIMIT 1001) t;
    SELECT * INTO analysis FROM canca.finding_analyses WHERE bundle_id=wanted_bundle AND policy_version='0.6.4';
    IF analysis.analysis_id IS NOT NULL AND analysis.evaluation_count>2000 THEN
        RAISE EXCEPTION 'legacy snapshot bound' USING ERRCODE='54000';
    END IF;
    SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY t.ordinal),'[]'::jsonb) INTO evaluations
        FROM (SELECT e.ordinal,e.source_path,e.source_sha256,e.rule_id,e.result,
              e.observation_ordinal,e.link_state,e.evidence_refs,f.finding_id,f.status AS finding_status,f.evidence
              FROM canca.finding_evaluations e LEFT JOIN canca.findings f
              ON f.analysis_id=e.analysis_id AND f.evaluation_ordinal=e.ordinal
              WHERE e.analysis_id=analysis.analysis_id ORDER BY e.ordinal LIMIT 2001) t;
    IF jsonb_array_length(observations)<>a.observation_count
       OR jsonb_array_length(artifacts)<>i.artifact_count
       OR jsonb_array_length(evaluations)<>COALESCE(analysis.evaluation_count,0) THEN
        RAISE EXCEPTION 'legacy snapshot conflict' USING ERRCODE='22000';
    END IF;
    result := jsonb_build_object('import',to_jsonb(i),'assets',to_jsonb(a),
        'artifacts',artifacts,'observations',observations,
        'analysis',CASE WHEN analysis.analysis_id IS NULL THEN NULL ELSE to_jsonb(analysis) END,
        'evaluations',evaluations);
    IF octet_length(result::text)>4194304 THEN
        RAISE EXCEPTION 'legacy snapshot bound' USING ERRCODE='54000';
    END IF;
    RETURN result;
END $$;
REVOKE ALL ON FUNCTION canca.workspace_legacy_snapshot(text) FROM PUBLIC;

CREATE TABLE canca.workspace_legacy_plans (
    workspace_id text NOT NULL, plan_id text NOT NULL,
    model_plan_id text NOT NULL, payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
    PRIMARY KEY (workspace_id,plan_id),
    FOREIGN KEY (workspace_id,model_plan_id) REFERENCES canca.workspace_import_plans(workspace_id,plan_id)
);
CREATE TABLE canca.workspace_legacy_imports (
    workspace_id text NOT NULL, collection_id text NOT NULL, assessment_id text NOT NULL,
    source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    source_snapshot jsonb NOT NULL CHECK (jsonb_typeof(source_snapshot)='object'),
    object_links jsonb NOT NULL CHECK (jsonb_typeof(object_links)='array'),
    author_role text NOT NULL DEFAULT current_user, created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,collection_id),
    FOREIGN KEY (workspace_id,collection_id) REFERENCES canca.workspace_collections(workspace_id,collection_id),
    FOREIGN KEY (workspace_id,assessment_id) REFERENCES canca.workspace_assessments(workspace_id,assessment_id)
);
DO $$ DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['workspace_legacy_plans','workspace_legacy_imports'] LOOP
        EXECUTE format('ALTER TABLE canca.%I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('ALTER TABLE canca.%I FORCE ROW LEVEL SECURITY',t);
        EXECUTE format('CREATE POLICY legacy_read ON canca.%I FOR SELECT USING
            (workspace_id=current_setting(''canca.workspace_id'',true) AND canca.workspace_model_allowed(false))',t);
        EXECUTE format('CREATE POLICY legacy_insert ON canca.%I FOR INSERT WITH CHECK
            (workspace_id=current_setting(''canca.workspace_id'',true) AND canca.workspace_model_allowed(true))',t);
    END LOOP;
END $$;
CREATE TRIGGER workspace_revision_stamp BEFORE INSERT ON canca.workspace_legacy_imports
FOR EACH ROW EXECUTE FUNCTION canca.workspace_revision_stamp();
CREATE POLICY legacy_author ON canca.workspace_legacy_imports AS RESTRICTIVE FOR INSERT
WITH CHECK (author_role=current_user);
-- Plans/history are immutable: no application UPDATE/DELETE policy.
