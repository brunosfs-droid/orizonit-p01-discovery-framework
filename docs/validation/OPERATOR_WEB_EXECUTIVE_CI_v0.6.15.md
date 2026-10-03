# Operator Web executive export v0.6.15 — qualification record

03/10/2026 (-03). **CANDIDATE; CI qualification in progress.**
The maintainer asked to continue development while manual LAB tests are deferred.
No new manual acceptance is claimed or requested today.

## Scope

The Web listener adds an executive ZIP download using the unchanged v0.6.14
synthesis and v0.6.9 complete collector. Both download kinds share the existing
bounded slot/deadline and authentication/read-grant boundary. Technical payload
and delivery versions remain 0.6.9/0.6.13; executive content/delivery are
0.6.14/0.6.15. API/auth, collector and executive CLI sources remain unchanged.

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

Executable source revision, run IDs and measured results will be recorded after
the CI matrix completes. Database-free opt-in skips do not qualify PostgreSQL.

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
