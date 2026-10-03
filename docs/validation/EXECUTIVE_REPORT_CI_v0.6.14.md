# Executive report v0.6.14 — qualification record

03/10/2026 (-03). **Code CI qualified; operational LAB CANDIDATE.**
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

## Qualified source and Actions

Executable source revision:
`bb73c1c47cd741985ae2e09f7d9f258205605e19`.
Git tree: `cba92990f327814ace8eb552cc4d73b93731ebe3`.
[PR #114](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/114).
Subsequent qualification-document changes preserve this executable source.

All eight runs completed successfully on that exact head: sixteen actual jobs,
with nonempty executed steps. Both pull_request and push matrices passed.

| Workflow | pull_request | push | Jobs per event |
| --- | --- | --- | --- |
| Python CI | [37140520095](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140520095) | [37140517454](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140517454) | 1 |
| PostgreSQL CI | [37140520101](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140520101) | [37140517434](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140517434) | 2 |
| Operator Web CI | [37140520103](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140520103) | [37140517447](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140517447) | 1 |
| Optional Agent CI | [37140520110](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140520110) | [37140517452](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37140517452) | 4 |

## Results and practical limits

- Python 3.12 suite: **443 cases, 338 executed / 105 optional skips**, PASS.
  All eleven new synthetic executive cases executed. The local suite matched
  these counts; local Web events passed nine behavior groups.
- PostgreSQL **16.15 and 17.11**: **184 cases each, PASS**, including all four
  new executive integration cases actually executed rather than skipped.
  The real SELECT-only CLI reads six data pages plus the terminal empty query,
  saves four historical occurrences in two groups after a later clean run,
  and preserves all fourteen table snapshots and evidence-store hashes.
  Missing/pending/inconclusive coverage, absent source store/current catalog,
  and a concurrent lifecycle writer were also checked.
- Existing real database/store backup-restore smoke: PASS on both versions,
  fourteen tables / twenty files, source revalidation and replay preserved.
  This regression check is separate from the executive output's
  `source_bytes_revalidated=false` semantics.
- Existing Web regression: nine event groups and actual Chromium desktop/mobile
  login/report/download flow, complete ZIP/hash verification, PASS. No Web source
  changed; this does not qualify a graphical executive view or PDF renderer.
- Existing agent/service regression: Linux Python 3.10/3.12 and Windows
  Python 3.12/3.13, including actual systemd/SCM lifecycle, interruption, tamper
  and scheduled offline soak, PASS. No service/collector source changed.

Skipped opt-in cases in the database-free Python suite do not qualify PostgreSQL;
only the real database matrix jobs supply that evidence. Fixed failure JSONs
printed by negative contract tests are expected; the test runners and independent
backup-restore smoke completed successfully.

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
