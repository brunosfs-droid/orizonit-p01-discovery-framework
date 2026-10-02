-- Explicit administrative lifecycle; no conclusion is inferred from imports.
ALTER TABLE canca.assessments
    ADD COLUMN lifecycle_state text NOT NULL DEFAULT 'registered'
        CHECK (lifecycle_state IN ('registered','active','review_required','completed','cancelled')),
    ADD COLUMN lifecycle_revision bigint NOT NULL DEFAULT 0 CHECK (lifecycle_revision >= 0);

CREATE TABLE canca.assessment_events (
    assessment_id text NOT NULL REFERENCES canca.assessments(assessment_id),
    revision bigint NOT NULL CHECK (revision > 0),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    actor_ref text NOT NULL CHECK (actor_ref ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    from_state text NOT NULL,
    to_state text NOT NULL,
    reason_code text NOT NULL,
    occurred_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (assessment_id, revision),
    UNIQUE (assessment_id, request_id),
    CHECK (
        (from_state = 'registered' AND to_state = 'active' AND reason_code = 'operator_start') OR
        (from_state = 'active' AND to_state = 'review_required' AND reason_code = 'operator_review') OR
        (from_state = 'review_required' AND to_state = 'active' AND reason_code = 'operator_resume') OR
        (from_state = 'active' AND to_state = 'completed' AND reason_code = 'operator_complete') OR
        (from_state IN ('registered','active','review_required') AND to_state = 'cancelled' AND reason_code = 'operator_cancel')
    )
);
