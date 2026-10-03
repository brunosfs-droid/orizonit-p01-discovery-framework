# ADR 0027 — Executive download in the operator Web

03/10/2026 (-03). Scope A — MVP. Implementation/CI qualification in progress;
operational LAB CANDIDATE. The maintainer has deferred manual tests today.

## Decision

Expose the qualified historical executive synthesis v0.6.14 through the existing
operator Web, with a separate explicit download button. Add
`GET /api/v1/assessments/{id}/report/executive/export`. Require the existing Bearer
session, exact assessment read grant, same-origin/Host boundary and mandatory
`expected_scope_sha256` before any database work. Optional `limit=1..100` controls
query paging only; the browser requests the complete displayed scope with the
default 100, independent of its table page size or edited assessment input.

Extend the current in-memory delivery service with two fixed internal kinds.
Both share one nonqueued semaphore slot and the existing 60-second cooperative
deadline. Collect the complete canonical technical report under its scope fence
and terminal empty query, then summarize it with the unchanged executive module.
Check session/grant/deadline before/after queries, after synthesis/serialization
and before returning the archive. Keep the slot while the handler writes bytes.
An active SQL statement retains its 30-second timeout; client abort does not
immediately cancel SQL. A second download of either kind returns 429 before SQL.

The executive ZIP has four fixed uncompressed root members: `executive.json`,
`executive.md`, `manifest.json`, `manifest.json.sha256`. Its content version is
0.6.14 and delivery version 0.6.15. Preserve the technical route's content 0.6.9
and delivery manifest 0.6.13 so its existing file verifier remains compatible.
Both archives retain 32 MiB bounds, fixed ZIP metadata, payload/manifest hashes,
HTTP scope/archive SHA256, attachment headers and no-store policy. No files are
written to the server and neither download opens the evidence store.

The client disables both buttons during any request, verifies type, kind-specific
filename, declared/actual length, scope and SHA256, then creates a temporary Blob.
Logout/expiry/reset suppress late downloads and revoke URLs. The report page is
preserved for recoverable failures and cleared on access denial/not found/scope
conflict; a saved artifact requires the operator's local data handling.

No new executive semantics, severity computation, finding closure, collection,
credentials, AD, migration, dependencies or role changes. The original API v0.6.11,
technical collector v0.6.9 and executive CLI v0.6.14 remain unchanged. Historical
v0.6.13 LAB guides and installer sources stay pinned to their qualified Git
revision; their launcher intentionally rejects a newer Web revision. Mocked
launcher tests must identify the historical listener version rather than assume
future HEAD still advertises it. New development does not rewrite that package.

## Verification and limits

HTTP tests cover grant/origin/query checks before SQL, complete executive contents,
fixed redacted errors, aggregate byte/deadline limits, shared-slot contention and
session revocation during collection/synthesis. PostgreSQL 16/17 verifies a real
SELECT-only HTTP reader against the canonical executive summary, all pages,
historical findings and unchanged fourteen tables/store. Client events cover
kind-specific validation, both-button locking and logout/expiry races. Actual
Chromium downloads at desktop/mobile widths verify both ZIP kinds and hashes.

CI qualifies synthetic environments; new operational executive download and the
earlier v0.6.13 download gates remain deferred. Prior accepted LAB gates are not
repeated. PDF, graphical executive rendering, public hosting, Windows ACLs and
production qualification remain outside this increment.

[Executive contract](ADR_0026_Executive_Report_v0.6.14.md) ·
[Technical delivery](ADR_0025_Operator_Web_Report_Export_v0.6.13.md) · [MVP](MVP.md).
