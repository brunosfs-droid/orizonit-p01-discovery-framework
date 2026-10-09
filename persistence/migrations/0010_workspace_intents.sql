-- Opt-in maintenance upgrade. Existing journal and content tables remain intact.
DO $$ BEGIN
    IF NOT pg_try_advisory_xact_lock(-2660897858987708572::bigint) THEN
        RAISE EXCEPTION 'workspace coordinator is active' USING ERRCODE='55006';
    END IF;
END $$;
CREATE TABLE canca.workspace_scan_intents (
    workspace_id text NOT NULL REFERENCES canca.workspaces,
    intent_id text NOT NULL CHECK (intent_id ~ '^intent-[0-9a-f]{32}$'),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    author_role text NOT NULL DEFAULT current_user,
    generation bigint NOT NULL CHECK (generation>=0),
    lease_sha256 text NOT NULL CHECK (lease_sha256 ~ '^[0-9a-f]{64}$'),
    scope_id text NOT NULL CHECK (scope_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    mode text NOT NULL CHECK (mode IN ('auth_only','full_enrichment')),
    scope_sha256 text NOT NULL CHECK (scope_sha256 ~ '^[0-9a-f]{64}$'),
    ttl_seconds integer NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 300),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,intent_id),
    UNIQUE (workspace_id,author_role,request_id),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '300 seconds')
);
CREATE TABLE canca.workspace_scan_decisions (
    workspace_id text NOT NULL, intent_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence BETWEEN 1 AND 2),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    decision text NOT NULL CHECK (decision IN ('approved','rejected','revoked','consumed')),
    author_role text NOT NULL DEFAULT current_user,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_revision bigint NOT NULL,
    PRIMARY KEY (workspace_id,intent_id,sequence),
    UNIQUE (workspace_id,author_role,request_id),
    FOREIGN KEY (workspace_id,intent_id) REFERENCES canca.workspace_scan_intents(workspace_id,intent_id)
);
DO $$ DECLARE t text; BEGIN
    FOREACH t IN ARRAY ARRAY['workspace_scan_intents','workspace_scan_decisions'] LOOP
        EXECUTE format('ALTER TABLE canca.%I ENABLE ROW LEVEL SECURITY',t);
        EXECUTE format('ALTER TABLE canca.%I FORCE ROW LEVEL SECURITY',t);
        EXECUTE format('CREATE POLICY intent_read ON canca.%I FOR SELECT USING
            (workspace_id=current_setting(''canca.workspace_id'',true) AND canca.workspace_model_allowed(false))',t);
        EXECUTE format('CREATE POLICY intent_insert ON canca.%I FOR INSERT WITH CHECK
            (workspace_id=current_setting(''canca.workspace_id'',true) AND canca.workspace_model_allowed(true) AND author_role=current_user)',t);
        EXECUTE format('CREATE TRIGGER z_revision BEFORE INSERT ON canca.%I FOR EACH ROW EXECUTE FUNCTION canca.workspace_revision_stamp()',t);
    END LOOP;
END $$;
-- Invoker trigger: current_user remains the authenticated, membership-checked role.
-- Serialize even raw INSERT callers through the workspace revision lock.
CREATE FUNCTION canca.workspace_intent_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,canca AS $$
DECLARE item canca.workspace_scan_intents; last_event text; last_sequence integer;
BEGIN
    PERFORM canca.workspace_revision_lock(true);
    IF NEW.author_role<>current_user THEN
        RAISE EXCEPTION 'intent identity denied' USING ERRCODE='42501';
    END IF;
    IF TG_TABLE_NAME='workspace_scan_intents' THEN
        IF NEW.generation<>current_setting('canca.workspace_generation',true)::bigint
           OR NEW.lease_sha256<>encode(sha256(convert_to(current_setting('canca.workspace_lease',true),'UTF8')),'hex') THEN
            RAISE EXCEPTION 'intent context denied' USING ERRCODE='42501';
        END IF;
        NEW.created_at:=clock_timestamp();
        NEW.expires_at:=NEW.created_at+make_interval(secs=>NEW.ttl_seconds);
    ELSE
        SELECT * INTO item FROM canca.workspace_scan_intents
          WHERE workspace_id=NEW.workspace_id AND intent_id=NEW.intent_id;
        IF NOT FOUND OR item.generation<>current_setting('canca.workspace_generation',true)::bigint
           OR item.lease_sha256<>encode(sha256(convert_to(current_setting('canca.workspace_lease',true),'UTF8')),'hex')
           OR clock_timestamp()>=item.expires_at THEN
            RAISE EXCEPTION 'intent stale' USING ERRCODE='55000';
        END IF;
        SELECT decision,sequence INTO last_event,last_sequence FROM canca.workspace_scan_decisions
          WHERE workspace_id=NEW.workspace_id AND intent_id=NEW.intent_id ORDER BY sequence DESC LIMIT 1;
        IF NEW.sequence<>COALESCE(last_sequence,0)+1 OR NOT COALESCE((
            (last_event IS NULL AND NEW.decision IN ('approved','rejected','revoked'))
            OR (last_event='approved' AND NEW.decision IN ('revoked','consumed'))),false) THEN
            RAISE EXCEPTION 'intent transition denied' USING ERRCODE='55000';
        END IF;
        NEW.created_at:=clock_timestamp();
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION canca.workspace_intent_guard() FROM PUBLIC;
CREATE TRIGGER intent_guard BEFORE INSERT ON canca.workspace_scan_intents
FOR EACH ROW EXECUTE FUNCTION canca.workspace_intent_guard();
CREATE TRIGGER intent_guard BEFORE INSERT ON canca.workspace_scan_decisions
FOR EACH ROW EXECUTE FUNCTION canca.workspace_intent_guard();
-- No application UPDATE/DELETE policies; no executor, secret, target or command columns.
