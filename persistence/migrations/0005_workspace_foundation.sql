-- Opt-in foundation. Legacy rows/evidence are not assigned, moved or rewritten.
-- Application roles require explicit SQL privileges AND workspace grants.
CREATE TABLE canca.workspaces (
    workspace_id text PRIMARY KEY CHECK (workspace_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    organization text NOT NULL CHECK (length(organization) BETWEEN 0 AND 255),
    created_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE canca.workspace_grants (
    workspace_id text NOT NULL REFERENCES canca.workspaces DEFERRABLE INITIALLY DEFERRED,
    principal_role text NOT NULL CHECK (principal_role ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    permission text NOT NULL CHECK (permission IN ('workspace:read','workspace:write')),
    PRIMARY KEY (workspace_id, principal_role, permission)
);
CREATE TABLE canca.workspace_sites (
    workspace_id text NOT NULL REFERENCES canca.workspaces,
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    kind text NOT NULL CHECK (kind IN ('on_premises','remote','azure','aws','cloud','other')),
    parent_site_id text,
    PRIMARY KEY (workspace_id, site_id),
    CHECK (parent_site_id IS NULL OR parent_site_id <> site_id),
    FOREIGN KEY (workspace_id, parent_site_id) REFERENCES canca.workspace_sites (workspace_id, site_id)
);
CREATE TABLE canca.workspace_environments (
    workspace_id text NOT NULL REFERENCES canca.workspaces,
    environment_id text NOT NULL CHECK (environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    kind text NOT NULL CHECK (kind IN ('production','homologation','lab','other')),
    PRIMARY KEY (workspace_id, environment_id)
);
CREATE TABLE canca.workspace_assessments (
    workspace_id text NOT NULL REFERENCES canca.workspaces,
    assessment_id text NOT NULL REFERENCES canca.assessments,
    PRIMARY KEY (workspace_id, assessment_id),
    UNIQUE (assessment_id)
);

-- Application hierarchy is append-only. Reject forward parent references even
-- in a multi-row INSERT, which a foreign key alone would allow to form a cycle.
CREATE FUNCTION canca.workspace_site_parent_present() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog,canca AS $$
BEGIN
    IF NEW.parent_site_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM canca.workspace_sites
        WHERE workspace_id=NEW.workspace_id AND site_id=NEW.parent_site_id
    ) THEN
        RAISE EXCEPTION 'workspace parent unavailable' USING ERRCODE='23503';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER workspace_site_parent_present BEFORE INSERT ON canca.workspace_sites
FOR EACH ROW EXECUTE FUNCTION canca.workspace_site_parent_present();

ALTER TABLE canca.workspace_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE canca.workspace_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY own_workspace_grants ON canca.workspace_grants FOR SELECT
    USING (principal_role = current_user);

ALTER TABLE canca.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE canca.workspaces FORCE ROW LEVEL SECURITY;
-- A lightweight authorized registry: names/IDs only, no inventory materialization.
CREATE POLICY workspace_registry ON canca.workspaces FOR SELECT USING (
    EXISTS (SELECT 1 FROM canca.workspace_grants g
            WHERE g.workspace_id = workspaces.workspace_id AND g.principal_role = current_user)
);

ALTER TABLE canca.workspace_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE canca.workspace_sites FORCE ROW LEVEL SECURITY;
CREATE POLICY sites_read ON canca.workspace_sites FOR SELECT USING (
    workspace_id = current_setting('canca.workspace_id', true)
    AND EXISTS (SELECT 1 FROM canca.workspace_grants g
                WHERE g.workspace_id = workspace_sites.workspace_id AND g.principal_role = current_user)
);
CREATE POLICY sites_write ON canca.workspace_sites FOR INSERT WITH CHECK (
    workspace_id = current_setting('canca.workspace_id', true)
    AND EXISTS (SELECT 1 FROM canca.workspace_grants g WHERE g.workspace_id = workspace_sites.workspace_id
                AND g.principal_role = current_user AND g.permission = 'workspace:write')
);

ALTER TABLE canca.workspace_environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE canca.workspace_environments FORCE ROW LEVEL SECURITY;
CREATE POLICY environments_read ON canca.workspace_environments FOR SELECT USING (
    workspace_id = current_setting('canca.workspace_id', true)
    AND EXISTS (SELECT 1 FROM canca.workspace_grants g
                WHERE g.workspace_id = workspace_environments.workspace_id AND g.principal_role = current_user)
);
CREATE POLICY environments_write ON canca.workspace_environments FOR INSERT WITH CHECK (
    workspace_id = current_setting('canca.workspace_id', true)
    AND EXISTS (SELECT 1 FROM canca.workspace_grants g WHERE g.workspace_id = workspace_environments.workspace_id
                AND g.principal_role = current_user AND g.permission = 'workspace:write')
);

ALTER TABLE canca.workspace_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE canca.workspace_assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY assessments_read ON canca.workspace_assessments FOR SELECT USING (
    workspace_id = current_setting('canca.workspace_id', true)
    AND EXISTS (SELECT 1 FROM canca.workspace_grants g
                WHERE g.workspace_id = workspace_assessments.workspace_id AND g.principal_role = current_user)
);
-- No application UPDATE/DELETE/ownership/grant policy. Maintenance is explicit.
