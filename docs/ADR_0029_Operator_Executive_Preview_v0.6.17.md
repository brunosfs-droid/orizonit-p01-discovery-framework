# ADR 0029 — Executive report preview in Web v0.6.17

Date: 03/10/2026 (-03). Status: accepted for implementation; operational CANDIDATE.
Scope: A — MVP technical/executive reporting through the minimal operator Web.

## Decision

Add an explicit **Ver resumo executivo** action to a displayed assessment report.
Use the complete fenced canonical export and the unchanged executive synthesis
v0.6.14, then project a bounded read-only JSON view: coverage/pending counts,
identity decisions, recorded severity counts and recommendation group summaries.
Do not deliver occurrence IDs, source/evidence paths, raw/extracted evidence or
arbitrary extras in this view. Full occurrence references remain in the executive
download. Preserve historical catalog/engine hashes and rule metadata per group.

The Web-only endpoint is `GET /api/v1/assessments/{id}/report/executive`, requiring
the exact assessment grant and the mandatory displayed `expected_scope_sha256`.
Optional `group_offset` selects a page of ten groups in the canonical severity/
rule/catalog/engine order. Offsets are aligned to ten and bounded by the existing
100-import/two-rule limit (200 groups). Each request recollects the complete fenced
assessment, including its terminal empty query; no server cache or implicit latest.
An out-of-range continuation or a changed scope fails without a partial preview.

Factor the qualified delivery's slot/deadline/collection window into a public
context manager shared by technical ZIP, executive ZIP and executive preview.
One slot, no queue/retry, 60-second cooperative deadline, auth checks throughout
collection/synthesis/serialization and immediately before sending. Keep the slot
through the socket write; release it on every exit. Keep ZIP member names,
technical content/delivery 0.6.9/0.6.13 and executive content/delivery 0.6.14/0.6.15
unchanged. Policy directory JSON remains v0.6.16, independent of the Web version.

Preview JSON has its own v0.6.17 contract and a 1 MiB limit, with scope/SHA256
headers. The browser checks MIME/length/scope/hash before parsing, validates
bounded counters/text/groups/pagination and renders text-only cards. It never
infers current risk, safety from no findings, remediation or automatic closure.

## Session and interaction behavior

No automatic preview on login, assessment selection or technical pagination.
First view and explicit recommendation pagination use the captured assessment
and displayed scope. Technical pagination stays independent; a new report query
or selector change clears the preview. Hide clears preview data in memory.
All long operations share the existing client busy guard; logout remains usable.
Logout/expiry/page restoration abort requests, clear data and suppress late
responses across generations. Manual editing still preserves displayed scope.
Recoverable preview failures clear that preview while retaining the technical
page; 403/404/409 clear both, and 401 resets the session.

## Verification and limits

Unit/HTTP tests cover complete history, real group pagination, whitelisted
projection, early denials, shared cross-kind slot, deadline/size, revocation and
slot release. PostgreSQL 16/17 reader CI verifies canonical equality and unchanged
14 tables/store. Event/Chromium desktop/mobile checks cover provenance/text-only
rendering, empty and many-group views, captured scope, pagination, hide, logout/
expiry races and compatibility of both downloaded ZIP formats.

No new migration, SQL writes, store access, collector login, target access,
dependency, AD/SSO, risk scoring, inventory/mapper or deployment. Previously
qualified LAB packages retain their pins; manual tests remain deferred at the
maintainer's request. No new LAB action is requested today.
