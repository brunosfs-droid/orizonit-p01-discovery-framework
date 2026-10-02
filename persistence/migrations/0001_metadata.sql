CREATE TABLE canca.assessments (
    assessment_id text PRIMARY KEY
);
CREATE TABLE canca.nodes (
    node_id text PRIMARY KEY
);
CREATE TABLE canca.runs (
    assessment_id text NOT NULL REFERENCES canca.assessments,
    run_id text NOT NULL,
    node_id text NOT NULL REFERENCES canca.nodes,
    PRIMARY KEY (assessment_id, run_id, node_id)
);
CREATE TABLE canca.imports (
    bundle_id text PRIMARY KEY CHECK (bundle_id ~ '^bnd-[0-9a-f]{20}$'),
    assessment_id text NOT NULL,
    run_id text NOT NULL,
    node_id text NOT NULL,
    bundle_sha256 text NOT NULL CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    receipt_sha256 text NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
    projection_sha256 text NOT NULL CHECK (projection_sha256 ~ '^[0-9a-f]{64}$'),
    imported_at_utc timestamptz NOT NULL,
    indexed_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    artifact_count integer NOT NULL CHECK (artifact_count > 0),
    FOREIGN KEY (assessment_id, run_id, node_id) REFERENCES canca.runs
);
CREATE TABLE canca.artifacts (
    bundle_id text NOT NULL REFERENCES canca.imports,
    path text NOT NULL,
    role text NOT NULL CHECK (role IN ('network_discovery', 'credentialed_evidence', 'assessment_manifest', 'asset_resolver')),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    PRIMARY KEY (bundle_id, path)
);
