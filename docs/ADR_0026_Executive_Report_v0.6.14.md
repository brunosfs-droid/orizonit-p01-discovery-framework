# ADR 0026 — Historical executive report

03/10/2026 (-03). Scope A — MVP. Implementation and CI qualification in progress;
manual LAB qualification deferred at the maintainer's request.

## Decision

Add a separate local read-only CLI, `persistence/P01_Executive_Report.py`, with
JSON and Markdown output. Reuse the complete canonical report collector, its
scope fence and terminal empty query. Keep the eleven pinned v0.6.13 package
sources unchanged: its pending Web download qualification is independent.
No database migration, SQL write, store access or new runtime dependency.

Summarize persisted imports, projection gaps, evaluation outcomes, asset identity
decisions and historical finding occurrences. Include explicit empty/pending
coverage and inconclusive outcomes; counts never establish whole-environment
coverage. Lifecycle remains administrative and later `no_finding` evaluations
do not resolve earlier occurrences. Do not compute a global risk score, current
vulnerability inventory, remediation status, SLA or unique vulnerability count.

Consolidate recommendations only for recorded findings, by exact stored rule ID,
rule version, policy version, catalog SHA256 and engine SHA256. Validate the
stored catalog/rule mapping and preserve its title, category, severity and
recommendation. Different historical catalogs/engines stay separate even if
their text happens to match. Presentation sorts saved severities Critical,
High, Medium, Low, Informational; other nonempty values remain explicit and sort
after them. This order is not a new severity assessment or remediation promise.

Each group carries a deterministic ID and all occurrence references: finding,
analysis/ordinal, bundle, source SHA256, central asset/decision and stored status.
Counts of distinct linked assets describe this historical set only. References
support traceability to the technical report; they do not independently verify
raw evidence. Exclude extracted evidence, evidence references, source paths and
raw payloads from executive output. Copy only specified metadata fields; no
arbitrary input fields flow into the artifact. Output is still confidential
assessment data and requires the operator's local access controls.

Publish `executive.json`, `executive.md`, `manifest.json` and
`manifest.json.sha256` together into a new private directory. Validate and bound
all bytes before creating staging files; maximum 32 MiB for the complete output
set, with no truncation. Use exclusive writes, file fsync and directory rename
on the same filesystem. Directory mode 0700 and file mode 0600 are qualified on
POSIX; Windows ACLs and crash durability of the directory rename are not covered.
The CLI uses the existing explicit libpq settings and SELECT-only report role;
there is no password/DSN argument or new Cancã login for portable collection.

## Verification and limits

Synthetic tests cover historical grouping, preserved recommendations, severity
variants, incomplete/conflicting metadata, empty/pending/inconclusive coverage,
safe Markdown, fixed failure codes, private publication and failure cleanup.
PostgreSQL 16/17 CI proves complete pagination under a SELECT-only role, canonical
agreement, historical findings after a later clean run, concurrent scope changes
and unchanged fourteen tables/store files. CI fixtures are disposable and must
not be run against the maintainer's LAB or a customer database.

The local CLI is a CANDIDATE until its own future LAB gate. The v0.6.13 download
gate remains pending; the already accepted recovery, lifecycle, technical export,
API and Web v0.6.12 gates are preserved. Web/API integration, PDF and graphical
renderer qualification are subsequent increments, not claimed by this CLI.

[MVP](MVP.md) · [Technical export](ADR_0020_Report_Export_v0.6.9.md) ·
[Web download](ADR_0025_Operator_Web_Report_Export_v0.6.13.md).
