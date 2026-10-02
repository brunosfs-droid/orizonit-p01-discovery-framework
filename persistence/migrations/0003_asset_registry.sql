-- Persistent, assessment-scoped identity. No inferred association backfill.
ALTER TABLE canca.imports ADD CONSTRAINT imports_bundle_assessment UNIQUE (bundle_id, assessment_id);

CREATE TABLE canca.assets (
    assessment_id text NOT NULL REFERENCES canca.assessments(assessment_id),
    asset_id text NOT NULL CHECK (asset_id ~ '^cas-[0-9a-f]{32}$'),
    created_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (assessment_id, asset_id)
);
CREATE TABLE canca.asset_imports (
    bundle_id text PRIMARY KEY,
    assessment_id text NOT NULL,
    projection_sha256 text NOT NULL CHECK (projection_sha256 ~ '^[0-9a-f]{64}$'),
    policy_version text NOT NULL CHECK (policy_version = '0.6.3'),
    observation_count integer NOT NULL CHECK (observation_count BETWEEN 0 AND 10000),
    projected_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (bundle_id, assessment_id),
    FOREIGN KEY (bundle_id, assessment_id) REFERENCES canca.imports(bundle_id, assessment_id)
);
CREATE TABLE canca.asset_observations (
    bundle_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 9999),
    assessment_id text NOT NULL,
    asset_id text NOT NULL,
    source_asset_id text NOT NULL CHECK (source_asset_id ~ '^ast-[0-9a-f]{16}$'),
    decision text NOT NULL CHECK (decision IN ('new_asset','linked','review_required')),
    reason_code text NOT NULL CHECK (reason_code IN ('new_identity','corroborated_identity','insufficient_identity',
        'local_conflict','strong_conflict','multiple_candidates','uncorroborated_candidate','candidate_bound_exceeded','history_bound_exceeded')),
    candidates jsonb NOT NULL CHECK (jsonb_typeof(candidates) = 'array'),
    candidates_truncated boolean NOT NULL,
    signals jsonb NOT NULL CHECK (jsonb_typeof(signals) = 'array'),
    source_refs jsonb NOT NULL CHECK (jsonb_typeof(source_refs) = 'array'),
    PRIMARY KEY (bundle_id, ordinal),
    FOREIGN KEY (bundle_id, assessment_id) REFERENCES canca.asset_imports(bundle_id, assessment_id),
    FOREIGN KEY (assessment_id, asset_id) REFERENCES canca.assets(assessment_id, asset_id)
);
CREATE INDEX asset_observations_identity ON canca.asset_observations(assessment_id,asset_id);
CREATE TABLE canca.asset_signals (
    assessment_id text NOT NULL,
    asset_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('serial_number','ssh_host_key_sha256','fqdn','hostname','ip','mac')),
    value text NOT NULL CHECK (length(value) BETWEEN 1 AND 255),
    qualified boolean NOT NULL,
    eligible boolean NOT NULL,
    PRIMARY KEY (assessment_id,asset_id,kind,value,qualified,eligible),
    FOREIGN KEY (assessment_id,asset_id) REFERENCES canca.assets(assessment_id,asset_id)
);
CREATE INDEX asset_signals_lookup ON canca.asset_signals(assessment_id,kind,value) WHERE eligible;
