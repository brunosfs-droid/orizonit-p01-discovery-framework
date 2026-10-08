#!/usr/bin/env python3
"""R01/R03: read-only readiness for one explicitly mapped legacy import.

This is not a migration, not an automatic approval of reconciliation decisions,
and not evidence that collections outside the historical schema4 store exist.
The caller must first obtain a SQL-authorized, workspace-scoped snapshot; only
then may trusted server configuration select the original on-disk source.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "persistence"))
import P01_Workspace_Legacy as legacy

model, pg, runtime, ws = legacy.model, legacy.pg, legacy.runtime, legacy.ws
VERSION = "0.6.38"


def inspect(conn, workspace_id, token, snapshot, projection, *, expected_revision=None):
    """Compare a verified source to current immutable migration receipts.

    The returned classification is a point-in-time observation and must be
    followed by a fresh preview/apply, which independently checks all fences.
    """
    if expected_revision is not None:
        runtime.require_generation(expected_revision)
    # Never use an untrusted source to derive an authorization decision.
    legacy.validate_snapshot(snapshot, projection)
    bundle_id = projection["import"]["bundle_id"]
    assessment_id = projection["import"]["assessment_id"]
    with legacy.scope(conn, workspace_id, token) as revision:
        if expected_revision is not None:
            model.check_revision(expected_revision, revision)
        # The mapping and source snapshot must still be the *same* after I/O.
        pg.require(legacy._snapshot(conn, bundle_id) == snapshot,
                   "legacy_source_conflict")
        row = conn.execute(
            "SELECT assessment_id,source_sha256,source_snapshot "
            "FROM canca.workspace_legacy_imports "
            "WHERE workspace_id=%s AND collection_id=%s",
            (workspace_id, bundle_id),
        ).fetchone()
        source_sha = model.digest(snapshot)
        if row is not None:
            pg.require(row[0] == assessment_id and row[1] == source_sha
                       and row[2] == snapshot, "legacy_source_conflict")
        return {
            "status": "already_backfilled" if row is not None else "preview_required",
            "readiness_version": VERSION,
            "workspace_id": workspace_id,
            "collection_id": bundle_id,
            "assessment_id": assessment_id,
            "revision": revision,
            "source_integrity": "verified_at_read",
            "identity_scope": "identity_only",
            "observation_count": len(snapshot["observations"]),
            "evaluation_count": len(snapshot["evaluations"]),
            "historical_analysis": ("recorded" if snapshot["analysis"] is not None
                                     else "not_analyzed"),
            "automatic_apply": False,
            "migration_complete": False,
        }
