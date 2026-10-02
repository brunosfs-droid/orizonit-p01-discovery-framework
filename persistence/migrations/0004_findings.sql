-- Immutable, source-bound evaluations and finding occurrences; no inferred backfill.
CREATE TABLE canca.finding_analyses (
    analysis_id text PRIMARY KEY CHECK (analysis_id ~ '^ana-[0-9a-f]{32}$'),
    bundle_id text NOT NULL,
    assessment_id text NOT NULL,
    policy_version text NOT NULL CHECK (policy_version = '0.6.4'),
    projection_sha256 text NOT NULL CHECK (projection_sha256 ~ '^[0-9a-f]{64}$'),
    import_projection_sha256 text NOT NULL CHECK (import_projection_sha256 ~ '^[0-9a-f]{64}$'),
    asset_projection_sha256 text NOT NULL CHECK (asset_projection_sha256 ~ '^[0-9a-f]{64}$'),
    engine_sha256 text NOT NULL CHECK (engine_sha256 ~ '^[0-9a-f]{64}$'),
    catalog_sha256 text NOT NULL CHECK (catalog_sha256 ~ '^[0-9a-f]{64}$'),
    catalog jsonb NOT NULL CHECK (jsonb_typeof(catalog) = 'object'),
    evaluation_count integer NOT NULL CHECK (evaluation_count BETWEEN 0 AND 2000),
    finding_count integer NOT NULL CHECK (finding_count BETWEEN 0 AND evaluation_count),
    recorded_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (bundle_id, policy_version),
    UNIQUE (analysis_id, bundle_id),
    FOREIGN KEY (bundle_id, assessment_id) REFERENCES canca.asset_imports(bundle_id, assessment_id)
);
CREATE TABLE canca.finding_evaluations (
    analysis_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 1999),
    bundle_id text NOT NULL,
    source_path text NOT NULL,
    source_sha256 text NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    rule_id text NOT NULL CHECK (rule_id IN ('WIN-FW-001','WIN-AD-001')),
    result text NOT NULL CHECK (result IN ('finding','no_finding','insufficient_evidence','not_applicable','not_supported')),
    observation_ordinal integer,
    link_state text NOT NULL CHECK (link_state IN ('unique_observation','ambiguous','unresolved')),
    evidence_refs jsonb NOT NULL CHECK (jsonb_typeof(evidence_refs) = 'array'),
    PRIMARY KEY (analysis_id, ordinal),
    UNIQUE (analysis_id, source_path, rule_id),
    CHECK ((observation_ordinal IS NOT NULL) = (link_state = 'unique_observation')),
    FOREIGN KEY (analysis_id, bundle_id) REFERENCES canca.finding_analyses(analysis_id, bundle_id),
    FOREIGN KEY (bundle_id, source_path) REFERENCES canca.artifacts(bundle_id, path),
    FOREIGN KEY (bundle_id, observation_ordinal) REFERENCES canca.asset_observations(bundle_id, ordinal)
);
CREATE TABLE canca.findings (
    finding_id text PRIMARY KEY CHECK (finding_id ~ '^fnd-[0-9a-f]{32}$'),
    analysis_id text NOT NULL,
    evaluation_ordinal integer NOT NULL,
    status text NOT NULL DEFAULT 'Open' CHECK (status = 'Open'),
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    UNIQUE (analysis_id, evaluation_ordinal),
    FOREIGN KEY (analysis_id, evaluation_ordinal) REFERENCES canca.finding_evaluations(analysis_id, ordinal)
);
