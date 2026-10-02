# ADR 0012 — Opt-in ingestion indexing and explicit reconciliation

Date: 2026-10-02 (-03). Accepted design; v0.6.1 implementation CANDIDATE.
Scope A — MVP. Refs #63; follows PostgreSQL foundation ADR 0011.

## Decision

Add `--metadata-index postgres` to the ingestion API, default `off`. The common
offline importer remains authoritative. Publish the validated filesystem import
first, clean this request's staging while holding the bundle lock, then attempt
indexing through the v0.6.0 PostgreSQL component. No automatic schema migration,
startup sweep, job queue, retry, overwrite, receipt mutation or evidence deletion.
An API instance serves one store; concurrent processes writing the same filesystem
store remain unqualified. Each DB attempt uses its own autocommit connection and
explicit transaction; there is no shared connection across request threads.

The original receipt and raw bundle are the reconciliation source. The adapter
revalidates that source before connecting and binds its assessment/run/node/bundle
identity to the already validated request. File publication and DB commit are two
separate effects, not one distributed transaction. Process interruption after file
publication can leave a missing index; interruption after DB commit can lose the
response. Exact source replay converges through existing importer/DB idempotency.
No claim of host power-loss/fsync recovery is made by these process-level tests.

HTTP 201 `imported` and HTTP 200 `already_imported` retain their filesystem meaning.
Only opt-in responses add `metadata_index` with `indexed`, `already_indexed`,
`pending` (DB failure/missing row), or `review_required` (integrity, identity,
schema, configuration or conflict). No successful import is described as rolled
back because the database failed. Callers needing a usable index must check the
new field; a 2xx filesystem acknowledgment alone does not prove indexed metadata.
Errors are fixed codes without driver exceptions, credentials or source paths.
The portable node keeps its existing filesystem upload acknowledgment semantics.

An authorized receipt GET may report current index state after source validation;
it never indexes or migrates. The existing mTLS node check runs before any database
attempt. There is no new remote reconciliation endpoint, database configuration
parameter, arbitrary-path request or product RBAC surface.

Reconcile one reviewed import explicitly using the existing `index-import` CLI,
with external database settings and a separate scoped operator account. It verifies
source bytes and inserts atomically, or returns `already_indexed`/a fixed failure.
A `review_required` conflict must not be resolved by deleting records or altering
receipts. Offline imports use this same explicit command; their default pipeline
has no new database dependency.

## Validation and limits

Synthetic bundles: opt-in/off, identity binding, auth-before-index, fixed failures,
source preservation and staging cleanup. Real PostgreSQL 16/17: HTTP first/repeat,
readback, unavailable DB then reconciliation, restart after file publication,
process exit after DB commit before acknowledgment, concurrent duplicate requests,
rollback, conflicts and schema drift. Preserve all existing core and native service
checks. Deployment TLS/roles, backup/restore, multi-process filesystem writers,
full assessment lifecycle, assets/findings and Web/UI remain separate gates.

Corporate artifacts now target OneDrive/SharePoint per the user's 02/10/2026
direction. GitHub remains the engineering source; Google Drive is legacy. This
increment does not perform or claim completion of the general file migration.
