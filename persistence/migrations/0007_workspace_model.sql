-- One installation/database; maintenance upgrade requires no live coordinator.
DO $$ BEGIN
    IF NOT pg_try_advisory_xact_lock(-2660897858987708572::bigint) THEN
        RAISE EXCEPTION 'workspace coordinator is active' USING ERRCODE='55006';
    END IF;
END $$;
ALTER TABLE canca.workspace_runtime ADD COLUMN lease_pid integer;
UPDATE canca.workspace_runtime SET state='closed',workspace_id=NULL,lease_id=NULL,generation=generation+1;

CREATE TABLE canca.workspace_revisions (
    workspace_id text PRIMARY KEY REFERENCES canca.workspaces,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision>=0),
    last_txid bigint
);
INSERT INTO canca.workspace_revisions (workspace_id) SELECT workspace_id FROM canca.workspaces;
CREATE FUNCTION canca.workspace_revision_init() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,canca AS $$ BEGIN
    INSERT INTO canca.workspace_revisions (workspace_id) VALUES (NEW.workspace_id);
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION canca.workspace_revision_init() FROM PUBLIC;
CREATE TRIGGER workspace_revision_init AFTER INSERT ON canca.workspaces
FOR EACH ROW EXECUTE FUNCTION canca.workspace_revision_init();

-- Only a boolean fence is exposed, never the active workspace/lease metadata.
-- The shared row lock keeps close/open waiting until this transaction ends.
CREATE FUNCTION canca.workspace_active_fence() RETURNS boolean LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,canca AS $$
DECLARE r canca.workspace_runtime; wanted bigint;
BEGIN
    BEGIN
        wanted := current_setting('canca.workspace_generation',true)::bigint;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
    END;
    SELECT * INTO r FROM canca.workspace_runtime WHERE singleton FOR SHARE;
    RETURN COALESCE(r.state='open' AND r.workspace_id=current_setting('canca.workspace_id',true)
        AND r.generation=wanted AND r.lease_id=current_setting('canca.workspace_lease',true)
        AND EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND granted
            AND pid=r.lease_pid AND classid=3675428734::oid AND objid=3413159780::oid AND objsubid=1),false);
END $$;
REVOKE ALL ON FUNCTION canca.workspace_active_fence() FROM PUBLIC;

-- PostgreSQL's role setting is membership-checked, unlike a free-form actor GUC.
CREATE FUNCTION canca.workspace_model_allowed(writing boolean) RETURNS boolean LANGUAGE sql
SECURITY DEFINER SET search_path=pg_catalog,canca AS $$
    SELECT canca.workspace_active_fence() AND EXISTS (
        SELECT 1 FROM canca.workspace_grants g JOIN pg_roles p ON p.rolname=g.principal_role
        WHERE p.oid=CASE WHEN current_setting('role')='none' THEN session_user::regrole
                        ELSE current_setting('role')::regrole END
          AND g.workspace_id=current_setting('canca.workspace_id',true)
          AND (NOT writing OR g.permission='workspace:write'));
$$;
REVOKE ALL ON FUNCTION canca.workspace_model_allowed(boolean) FROM PUBLIC;
CREATE FUNCTION canca.workspace_revision_lock(writing boolean) RETURNS bigint LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,canca AS $$ DECLARE result bigint;
BEGIN
    IF NOT canca.workspace_model_allowed(writing) THEN
        RAISE EXCEPTION 'workspace context denied' USING ERRCODE='42501';
    END IF;
    IF writing THEN
        SELECT revision INTO result FROM canca.workspace_revisions
            WHERE workspace_id=current_setting('canca.workspace_id',true) FOR UPDATE;
    ELSE
        SELECT revision INTO result FROM canca.workspace_revisions
            WHERE workspace_id=current_setting('canca.workspace_id',true) FOR SHARE;
    END IF;
    RETURN result;
END $$;
REVOKE ALL ON FUNCTION canca.workspace_revision_lock(boolean) FROM PUBLIC;
CREATE FUNCTION canca.workspace_revision_stamp() RETURNS trigger LANGUAGE plpgsql
SECURITY DEFINER SET search_path=pg_catalog,canca AS $$
BEGIN
    IF NEW.workspace_id<>current_setting('canca.workspace_id',true)
       OR NOT canca.workspace_model_allowed(true) THEN
        RAISE EXCEPTION 'workspace context denied' USING ERRCODE='42501';
    END IF;
    UPDATE canca.workspace_revisions SET revision=revision+CASE WHEN last_txid=txid_current() THEN 0 ELSE 1 END,
        last_txid=txid_current() WHERE workspace_id=NEW.workspace_id RETURNING revision INTO NEW.created_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'workspace revision unavailable' USING ERRCODE='42501'; END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION canca.workspace_revision_stamp() FROM PUBLIC;

CREATE TABLE canca.workspace_objects (
    workspace_id text NOT NULL REFERENCES canca.workspaces,
    object_id text NOT NULL CHECK (object_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    kind text NOT NULL CHECK (kind IN ('host','device','interface','component','network','vlan','service','group','passive')),
    label text NOT NULL CHECK (length(label) BETWEEN 1 AND 255),
    site_id text, environment_id text,
    origin text NOT NULL CHECK (origin IN ('observed','declared')),
    author_role text NOT NULL DEFAULT current_user,
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,object_id),
    FOREIGN KEY (workspace_id,site_id) REFERENCES canca.workspace_sites(workspace_id,site_id),
    FOREIGN KEY (workspace_id,environment_id) REFERENCES canca.workspace_environments(workspace_id,environment_id)
);
CREATE TABLE canca.workspace_collections (
    workspace_id text NOT NULL REFERENCES canca.workspaces,
    collection_id text NOT NULL,
    bundle_sha256 text NOT NULL CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    projection_sha256 text NOT NULL CHECK (projection_sha256 ~ '^[0-9a-f]{64}$'),
    assessment_id text NOT NULL, run_id text NOT NULL, node_id text NOT NULL,
    received_at_utc timestamptz NOT NULL,
    mode text NOT NULL CHECK (mode IN ('merge','evidence_only')),
    categories jsonb NOT NULL CHECK (jsonb_typeof(categories)='array'),
    coverage text NOT NULL CHECK (coverage IN ('identity_only','partial','unknown')),
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,collection_id)
);
CREATE TABLE canca.workspace_observations (
    workspace_id text NOT NULL, collection_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 999), object_id text,
    source_asset_id text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('new_identity','corroborated_identity','manual_link','manual_create','evidence_only')),
    identity_eligible boolean NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    signals jsonb NOT NULL CHECK (jsonb_typeof(signals)='array'),
    source_refs jsonb NOT NULL CHECK (jsonb_typeof(source_refs)='array'),
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,collection_id,ordinal),
    FOREIGN KEY (workspace_id,collection_id) REFERENCES canca.workspace_collections(workspace_id,collection_id),
    FOREIGN KEY (workspace_id,object_id) REFERENCES canca.workspace_objects(workspace_id,object_id)
);
CREATE INDEX workspace_observation_history ON canca.workspace_observations(workspace_id,object_id,collection_id);
CREATE TABLE canca.workspace_identity_signals (
    workspace_id text NOT NULL, object_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('serial_number','ssh_host_key_sha256','fqdn','hostname','ip','mac')),
    value text NOT NULL CHECK (length(value) BETWEEN 1 AND 255),
    qualified boolean NOT NULL, eligible boolean NOT NULL,
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,object_id,kind,value,qualified,eligible),
    FOREIGN KEY (workspace_id,object_id) REFERENCES canca.workspace_objects(workspace_id,object_id)
);
CREATE INDEX workspace_identity_lookup ON canca.workspace_identity_signals(workspace_id,kind,value) WHERE eligible;
CREATE TABLE canca.workspace_declarations (
    workspace_id text NOT NULL, declaration_id text NOT NULL,
    object_id text NOT NULL, attribute text NOT NULL,
    value jsonb NOT NULL CHECK (jsonb_typeof(value) IN ('string','number','boolean','null')),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    author_role text NOT NULL DEFAULT current_user,
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,declaration_id),
    UNIQUE (workspace_id,object_id,attribute,created_revision),
    FOREIGN KEY (workspace_id,object_id) REFERENCES canca.workspace_objects(workspace_id,object_id)
);
CREATE INDEX workspace_declaration_history ON canca.workspace_declarations(workspace_id,object_id,attribute,created_revision);
CREATE TABLE canca.workspace_relationships (
    workspace_id text NOT NULL, relationship_id text NOT NULL, event_id text NOT NULL,
    source_id text NOT NULL, target_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('connected_to','hosted_on','member_of','depends_on','available_on','located_in')),
    active boolean NOT NULL, reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 1024),
    author_role text NOT NULL DEFAULT current_user,
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,relationship_id,event_id),
    UNIQUE (workspace_id,relationship_id,created_revision),
    CHECK (source_id<>target_id),
    FOREIGN KEY (workspace_id,source_id) REFERENCES canca.workspace_objects(workspace_id,object_id),
    FOREIGN KEY (workspace_id,target_id) REFERENCES canca.workspace_objects(workspace_id,object_id)
);
CREATE INDEX workspace_relationship_neighbors ON canca.workspace_relationships(workspace_id,source_id,target_id,created_revision);
CREATE TABLE canca.workspace_import_plans (
    workspace_id text NOT NULL REFERENCES canca.workspaces, plan_id text NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision>=0),
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
    preview jsonb NOT NULL CHECK (jsonb_typeof(preview)='array'),
    PRIMARY KEY (workspace_id,plan_id)
);
CREATE TABLE canca.workspace_model_requests (
    workspace_id text NOT NULL REFERENCES canca.workspaces, request_id text NOT NULL,
    payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    result jsonb NOT NULL CHECK (jsonb_typeof(result)='object'),
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,request_id)
);

DO $$ DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['workspace_revisions','workspace_objects','workspace_collections',
        'workspace_observations','workspace_identity_signals','workspace_declarations','workspace_relationships',
        'workspace_import_plans','workspace_model_requests'] LOOP
        EXECUTE format('ALTER TABLE canca.%I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('ALTER TABLE canca.%I FORCE ROW LEVEL SECURITY',t);
        EXECUTE format('CREATE POLICY model_read ON canca.%I FOR SELECT USING
            (workspace_id=current_setting(''canca.workspace_id'',true) AND canca.workspace_model_allowed(false))',t);
        IF t<>'workspace_revisions' THEN
            EXECUTE format('CREATE POLICY model_insert ON canca.%I FOR INSERT WITH CHECK
                (workspace_id=current_setting(''canca.workspace_id'',true) AND canca.workspace_model_allowed(true))',t);
        END IF;
        IF t NOT IN ('workspace_revisions','workspace_import_plans') THEN
            EXECUTE format('CREATE TRIGGER workspace_revision_stamp BEFORE INSERT ON canca.%I
                FOR EACH ROW EXECUTE FUNCTION canca.workspace_revision_stamp()',t);
        END IF;
    END LOOP;
END $$;
-- Authorship cannot be supplied on behalf of another database identity.
CREATE POLICY object_author ON canca.workspace_objects AS RESTRICTIVE FOR INSERT WITH CHECK (author_role=current_user);
CREATE POLICY declaration_author ON canca.workspace_declarations AS RESTRICTIVE FOR INSERT WITH CHECK (author_role=current_user);
CREATE POLICY relationship_author ON canca.workspace_relationships AS RESTRICTIVE FOR INSERT WITH CHECK (author_role=current_user);
-- No application UPDATE/DELETE: history, plan payloads and receipts stay immutable.
