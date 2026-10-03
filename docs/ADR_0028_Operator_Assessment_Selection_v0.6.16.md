# ADR 0028 — Operator assessment selection v0.6.16

Date: 03/10/2026 (-03). Status: accepted for implementation; operational CANDIDATE.
Scope: A — MVP usability of the minimal read-only operator Web interface.

## Decision

Add `GET /api/v1/operator/assessments` to the Web listener only. An active local
operator session receives the sorted, case-sensitive assessment IDs in its own
immutable startup policy. This is a directory of **grants**, not a database
inventory. It does not check existence, lifecycle, imports, assets or findings.
An absent database and a granted ID with no report do not prevent listing.

Extend `LocalAuth` with a public session-checked grant accessor returning an
immutable tuple under the existing lock. Keep its v0.6.11 authentication/session
contract and the standalone API listener unchanged. The Web version becomes
v0.6.16; policy format, exact report grants and existing export formats remain.

The route accepts GET with no query or body. Same-origin/Host rules and strict
Bearer parsing precede access. Recheck the session immediately before sending
the small JSON response. Existing policy limits allow at most 128 IDs of 128
ASCII characters; impose a 32 KiB response budget. Never return account records,
usernames, password hashes, tokens, other principals' IDs or database metadata.
Session expiry/logout/restart revokes listing as it revokes report access.

## Interaction

After login, load a native selector and offer an explicit refresh. Choosing an ID
fills the existing report form and clears the previous report; it does not query
or export automatically. The operator then chooses Consultar. Manual ID entry
remains available, including when the directory is unavailable, and still uses
the exact server-side grant check. Editing a draft ID keeps an already-displayed
report and its captured download scope, as in v0.6.13/v0.6.15.

Use text-only options, validate the list shape/order/uniqueness/ID bounds before
rendering, clear it on logout/expiry/page restoration, abort pending requests and
discard late responses across session generations. Disable selector/refresh
during an operation. Empty grants and directory failures have distinct messages.
No cookies, persistent browser storage or session renewal is introduced.

## Consequences and verification

HTTP and auth tests cover account isolation, case-sensitive IDs, empty/maximal
grants, redacted errors, rejected input/origins, revocation and no database calls.
Event and actual Chromium checks cover selection, explicit query, refresh,
fallback, logout/expiry races and desktop/mobile layout. PostgreSQL CI verifies
that policy grants can include a missing assessment while listing stays SQL-free,
report access remains exact and 14 tables/evidence files remain unchanged.

This is not assessment creation/listing from PostgreSQL, an import wizard,
tenancy, an admin role, AD integration or a collector login. Existing qualified
LAB packages stay at their Git pins. Manual LAB qualification is deferred at the
maintainer's request on 03/10; no new operational action is requested today.
