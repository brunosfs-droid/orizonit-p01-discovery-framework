-- Explicit runtime opt-in; a database represents one Cancã server installation.
-- Only the separately provisioned trusted coordinator role gets SELECT/UPDATE.
CREATE TABLE canca.workspace_runtime (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    principal_role text NOT NULL,
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    state text NOT NULL DEFAULT 'closed' CHECK (state IN ('closed','open','closing')),
    workspace_id text REFERENCES canca.workspaces,
    lease_id text,
    CHECK ((state='closed' AND workspace_id IS NULL) OR
           (state IN ('open','closing') AND workspace_id IS NOT NULL AND lease_id IS NOT NULL))
);
ALTER TABLE canca.workspace_runtime ENABLE ROW LEVEL SECURITY;
ALTER TABLE canca.workspace_runtime FORCE ROW LEVEL SECURITY;
CREATE POLICY coordinator_read ON canca.workspace_runtime FOR SELECT
    USING (principal_role=current_user);
CREATE POLICY coordinator_update ON canca.workspace_runtime FOR UPDATE
    USING (principal_role=current_user) WITH CHECK (principal_role=current_user);
-- No application INSERT/DELETE. Provisioning is an explicit maintenance operation.
