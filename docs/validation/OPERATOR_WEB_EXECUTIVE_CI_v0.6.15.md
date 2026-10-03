# Operator Web executive export v0.6.15 — qualification record

03/10/2026 (-03). **Code CI qualified; operational LAB CANDIDATE.**
The maintainer asked to continue development while manual LAB tests are deferred.
No new manual acceptance is claimed or requested today.

## Scope

The Web listener adds an executive ZIP download using the unchanged v0.6.14
synthesis and v0.6.9 complete collector. Both download kinds share the existing
bounded slot/deadline and authentication/read-grant boundary. Technical payload
and delivery versions remain 0.6.9/0.6.13; executive content/delivery are
0.6.14/0.6.15. At the qualified v0.6.15 source pin, API/auth, collector and
executive CLI sources remained unchanged. Later Web increments use their own pins.

Six new actual HTTP cases cover complete seven-query/six-page executive history,
authorization/origin/query denials before SQL, redacted backend failures,
cross-kind contention, byte/deadline limits and revocation during query/synthesis.
Three archive cases cover tamper/compression/extra members, malformed semantics,
duplicate JSON/finding IDs, forbidden evidence in references, standalone ASCII
CRLF execution and path redaction. Event tests cover both-button locking,
kind-specific filenames, displayed scope and logout/expiry races.

Real PostgreSQL 16/17 HTTP reader case compares with the canonical executive
synthesis: four evaluations, two historical findings, two recommendation groups,
four data pages plus terminal empty query, SELECT-only role, unchanged fourteen
tables and source-store hashes. Actual Chromium desktop/mobile downloads verify
both technical and executive archives and preserve no-cookie/storage behavior.

## Qualified source and Actions

Executable source: `2db86d56f3077babc00eacb0a94cb885e2966348`.
Git tree: `d519af99d774ede0e0e90038cd1f86d15b56a001`.
[PR #115](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/115).
Subsequent qualification-document changes preserve this executable source.
All eight exact-head runs completed successfully, with sixteen actual jobs and
nonempty executed steps; both pull_request and push matrices passed.

| Workflow | pull_request | push | Jobs per event |
| --- | --- | --- | --- |
| Python CI | [37146668209](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146668209) | [37146666328](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146666328) | 1 |
| PostgreSQL CI | [37146668155](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146668155) | [37146666335](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146666335) | 2 |
| Operator Web CI | [37146668222](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146668222) | [37146666332](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146666332) | 1 |
| Optional Agent CI | [37146668224](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146668224) | [37146666331](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37146666331) | 4 |

## Results

- Python 3.12: **453 cases, 347 executed / 106 optional skips**, PASS, matching
  the local suite. All nine new HTTP/archive cases executed; the real PostgreSQL
  case is opt-in in this database-free job.
- PostgreSQL **16.15 / 17.11**: **185 executed cases each, no skips**, PASS.
  The new reader-role HTTP executive case actually executed on both versions:
  complete four-page history plus terminal query, canonical summary equality,
  two historical Open findings after a later no_finding run, two groups, archive
  hashes, stale scope/denied assessment/logout rejection and unchanged fourteen
  table/store snapshots. UPDATE/DELETE/INSERT/CREATE attempts under that reader
  were denied. Existing real database/store backup-restore also passed on both
  versions with fourteen tables/twenty files and replay preserved.
- Client events: **eleven behavior groups**, PASS. The executive request uses
  the displayed assessment/fence, locks both buttons and rejects the technical
  attachment filename on an executive request. Recoverable failures keep
  the page; access/scope failures clear it. Logout/expiry races cover both kinds.
- Actual Chromium: **1280px desktop / 390px mobile**, PASS. Both kinds downloaded
  from page 1 while it displayed one evaluation; files contain all four evaluations
  and two historical findings, with two executive recommendation groups. No
  external requests, cookies, persistent session storage or injected HTML. New
  report screenshots were inspected: both download buttons are readable, mobile
  buttons span their container and only the evaluation table scrolls horizontally.
- Existing agent/service regression: four Linux/Windows Python combinations,
  actual systemd/SCM lifecycle, interruption/tamper and offline scheduled soak,
  PASS. No agent/service source changed.

Database-free skips do not qualify PostgreSQL; the real matrix jobs supply that
evidence. Fixed failure JSON printed by negative contract tests is expected and
does not change the successful runner/backup-restore conclusions.

## Browser artifact verification

Actions artifact `11282766035`, run `37146668222`, **384785 bytes**,
SHA256 `33fa6c57a038db786f2576b08ac5694d5848394c7c8cc7ac73d2544187140e9c`.
It contains four login/report PNGs and four actual downloaded ZIPs. The artifact
hash and fixed member inventory were checked before inspection. Retention is the
workflow's seven days; the source/run/hash record remains in Git.

Both executive archives were independently rechecked through the standalone
verifier: four members, four evaluations, two historical findings, two groups,
terminal fence and no raw/extracted evidence, PASS. Their identical archive
SHA256 is `c39b02f37f3816a731179fea1b09a800a27ad649a4d97193bdc3944fcd795cf3`.
Both technical archives also pass the unchanged v0.6.13 verifier; their identical
SHA256 is `8b828ed3efb3b7714efe4ce96b8158ec753dfc400a4d71c9a848b7d391418bb9`.
These comparisons use synthetic fixed timestamps and do not promise identical
hashes for distinct real database query times or establish source authenticity.

## Independent gates

- Technical Web download v0.6.13: manual download/verification remains pending.
- Executive CLI v0.6.14 and Web delivery v0.6.15: future operational LAB gates.
- Prior accepted synthetic LAB gates remain preserved; none is repeated today.
- No production/public-host, Windows ACL, graphical executive view or PDF claim.

Historical v0.6.13 installer sources stay at their qualified Git pin; its guides,
launcher and file verifier are unchanged. Positive tests of the mocked historical
launcher use its expected version; a v0.6.15 listener is explicitly rejected by
that launcher. This does not test or authorize a mixed-version installation.

[Contract](../OPERATOR_WEB_EXECUTIVE_v0.6.15.md) ·
[ADR 0027](../ADR_0027_Operator_Web_Executive_Export_v0.6.15.md).
