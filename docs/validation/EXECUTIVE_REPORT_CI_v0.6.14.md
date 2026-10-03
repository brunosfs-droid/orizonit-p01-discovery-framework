# Executive report v0.6.14 — qualification record

03/10/2026 (-03). **CANDIDATE; CI qualification in progress.**
The maintainer cannot perform LAB tests today and asked for independent development.
No new LAB acceptance is claimed or required to implement/qualify this increment.

## Scope

New local read-only executive CLI over the complete canonical historical report.
Synthetic coverage checks grouping, catalog/engine variants, saved severity values,
identity ambiguity, empty/pending/inconclusive coverage, whitelisted output,
inert Markdown, private publication, checksums, byte limits and redacted failures.

PostgreSQL 16/17 cases exercise real SELECT-only CLI collection/publication,
complete six-page history with four positive and two later negative evaluations,
two recommendation groups, fourteen table snapshots and source-store hashes.
Additional cases cover empty/pending/inconclusive reports, absent store/current
catalog isolation and a lifecycle writer after the last data page.

CI run IDs, tested revision and results will be recorded after completion.
Skipped opt-in cases in the database-free Python suite do not qualify PostgreSQL;
only real database matrix jobs supply that evidence.

## Independent gates

- Web download v0.6.13: manual Windows/Rocky download/verification remains pending.
- Executive CLI v0.6.14: future operational LAB gate; no manual acceptance yet.
- Earlier recovery/lifecycle/technical export/API/Web R1 acceptances are preserved.
- No production, public hosting, Windows filesystem ACL, PDF or graphical
  rendering qualification is claimed.

The eleven v0.6.13 source files remain byte-identical to the pinned
`9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871` package, so the postponed guide can
continue to use that revision when the maintainer is available.

[Contract](../EXECUTIVE_REPORT_v0.6.14.md) ·
[ADR](../ADR_0026_Executive_Report_v0.6.14.md) ·
[Web download qualification](OPERATOR_WEB_EXPORT_CI_v0.6.13.md).
