# ADR 0025 — Complete report download for local operators

03/10/2026 (-03). Code CI qualified; new download LAB gate CANDIDATE.
Web R1 v0.6.12 remains LAB VALIDATED.
[Qualification and limits](validation/OPERATOR_WEB_EXPORT_CI_v0.6.13.md).

## Decision

Complete the MVP report flow with an explicit download in the existing Web
listener. `GET /api/v1/assessments/{id}/report/export` requires the existing
Bearer session and exact `assessment:read` grant before database access.
`expected_scope_sha256` is mandatory; optional `limit=1..100` defaults to 100.
The browser always exports with limit 100 regardless of its displayed page size.
The original v0.6.11 API entry point keeps its routes and contract.

Reuse the canonical read-only report and v0.6.9 collector/Markdown renderer.
Extend the collector with optional initial scope and per-query checkpoint hooks;
existing CLI calls, content version and filesystem publication stay compatible.
Every page and the terminal empty query use the scope displayed in the browser.
A conflicting scope produces 409 and no download, with no automatic retry.
The archive contains all evaluations, including historical findings; pagination
in the UI does not limit the exported contents.

Build a ZIP in memory with four fixed root members: `report.json`, `report.md`,
`manifest.json`, `manifest.json.sha256`. ZIP entries use fixed metadata, stored
bytes and private file mode. JSON/Markdown preserve the existing content version;
the manifest additionally identifies delivery version 0.6.13. Manifest entries
record size/SHA256; the HTTP response also records archive SHA256 and report scope.
Nothing is written to the server filesystem, and the store is never opened.

The existing eight HTTP workers remain bounded. One export per listener may run
at a time; another receives 429 without a queue or database call. The archive is
bounded to 32 MiB. A 60-second monotonic deadline and session/grant checks run
before and after each canonical query and before sending. An in-progress query
retains the existing 30-second statement timeout; the deadline is cooperative,
not an asynchronous database cancellation. A browser timeout/abort does not
immediately cancel SQL. The slot is released on every server completion/failure.

Reuse Web Host/Origin checks, no-store, nosniff, same-origin policy and TLS/loopback
boundary. Content-Disposition uses a validated assessment ID and fixed suffix;
tokens/passwords never appear in filenames, URLs or the archive. The client
checks content type, declared/actual length, scope and archive SHA256 before
creating a temporary Blob download. Logout, expiry and page exit abort requests,
revoke Blob URLs and suppress late responses. An already saved file remains on
the operator's computer and requires their normal local data handling.

## Verification and qualification

Real HTTP negative tests prove authorization before database access, scope/query
validation, contention, byte/deadline bounds, cleanup and error redaction.
PostgreSQL 16/17 tests compare complete canonical history, terminal fence,
four archive members/hashes and all fourteen table/store invariants.
Event tests cover complete downloads, malformed responses, logout and expiry
races. Chromium desktop/mobile tests perform real downloads and verify their
contents through a bounded local verifier; browser tooling stays CI-only.

Historical v0.6.9/v0.6.12 install tests use their pinned Git sources, rather than
assuming future HEAD still contains old package bytes. CI fetches the needed
history. Their qualified guides, hashes and packages remain unchanged.

The only new manual LAB gate is download/verification through the established
Windows–Rocky loopback tunnel and new temporary launcher. It uses the recovered
synthetic database and SELECT-only snapshots, then removes its temporary account
and listener. Do not repeat restore, lifecycle, CLI export, API or Web v0.6.12.
No migration, collection, scan, node mTLS, credential-provider, role or AD change.
No background jobs, raw evidence ZIPs, PDF, topology or public-host qualification.

[Web boundary](ADR_0024_Local_Operator_Web_v0.6.12.md) ·
[CLI export](ADR_0020_Report_Export_v0.6.9.md) ·
[MVP](MVP.md).
