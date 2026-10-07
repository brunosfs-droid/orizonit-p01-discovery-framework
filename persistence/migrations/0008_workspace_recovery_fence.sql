-- A restored runtime must never borrow a lease from another database.
DO $$ BEGIN
    IF NOT pg_try_advisory_xact_lock(-2660897858987708572::bigint) THEN
        RAISE EXCEPTION 'workspace coordinator is active' USING ERRCODE='55006';
    END IF;
END $$;
CREATE OR REPLACE FUNCTION canca.workspace_active_fence() RETURNS boolean LANGUAGE plpgsql
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
            AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
            AND pid=r.lease_pid AND classid=3675428734::oid AND objid=3413159780::oid AND objsubid=1),false);
END $$;
REVOKE ALL ON FUNCTION canca.workspace_active_fence() FROM PUBLIC;

