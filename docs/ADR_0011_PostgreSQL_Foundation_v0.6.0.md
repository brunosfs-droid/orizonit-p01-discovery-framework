# ADR 0011 — PostgreSQL evidence metadata foundation v0.6.0

Date: 2026-10-02 (-03). Status: accepted design; implementation CANDIDATE.
Scope A — MVP. Refs #63. Distributed mTLS R2 has passed; scheduler extended
soak remains a separate LAB gate and does not prevent this independent increment.

## Decision

PostgreSQL is the central metadata database. The validated filesystem evidence
store remains the source of immutable raw bundles and original import receipts.
This first increment explicitly indexes one previously imported bundle at a time;
it does not change ingestion API, portable runtime or installed service behavior.
No automatic migration, directory sweep, raw evidence deletion or live LAB change.

Persist assessments, nodes, assessment/run/node identities, imports and artifact
provenance (role, bundle-relative path, SHA256 and size). Asset IDs, lifecycle states,
findings, Web/API queries and automatic index-on-ingest are later increments.
A receipt is an ingestion record, not proof of an authorized database principal.
No assessment status is inferred from a scheduler or import finishing.

Before opening a database connection for indexing, verify the receipt sidecar,
canonical import location, raw bundle digest and a private snapshot using the
existing bundle validator. Bind receipt identity/counts to that snapshot manifest;
reject duplicate keys, unsafe paths, invalid identity and noncanonical bundle ID.
Persist a narrow metadata projection rather than copying receipt/config/credentials.
Raw bundles, payload files and source receipts remain unchanged.

One transaction inserts all metadata; failures roll it back. Bundle ID is globally
unique in this database. The exact same projection is idempotent; a changed digest,
identity or receipt is a conflict and cannot overwrite the existing import.
Transaction advisory locks serialize same-bundle attempts. No merging by IP and no
cross-assessment asset correlation. Database unique/FK/check constraints enforce
basic invariants. A future multi-tenant design requires an explicit isolation ADR.

Migration 0001 has a stored checksum/version and a transaction-scoped lock. Only
an explicit migrate command changes schema. Unknown versions/checksum drift block
index/query; no migration rollback/destructive repair command is exposed.

Database settings and credentials come from libpq environment/passfile externally;
no DSN/password in CLI arguments, outputs, receipts or evidence. The CLI requires
explicit PGHOST/PGDATABASE/PGUSER, uses bounded connect/lock/statement timeouts and
fixed public errors. Remote database connections require verify-full TLS. Deployment
roles, TLS certificates, backups and database host provisioning remain operator-owned.
Migration uses a schema owner; operational indexing needs a separately scoped role.

## Validation and limits

Use synthetic validated bundles for snapshot/hash/identity/path/redaction unit tests.
CI provisions real disposable PostgreSQL 16 and 17 and exercises migration/restart,
readback, idempotency, concurrency, conflict and partial-write rollback. No SQLite
substitute is called PostgreSQL validation. The existing regression and native
SCM/systemd tests remain independent.

Candidate until actual Cancã Server PostgreSQL LAB, role permissions and backup/restore
are qualified. This is a queryable metadata foundation, not completed Product Alpha.

References: [Psycopg transactions](https://www.psycopg.org/psycopg3/docs/basic/transactions.html),
[PostgreSQL INSERT](https://www.postgresql.org/docs/16/sql-insert.html),
[transaction advisory locks](https://www.postgresql.org/docs/16/explicit-locking.html#ADVISORY-LOCKS).
