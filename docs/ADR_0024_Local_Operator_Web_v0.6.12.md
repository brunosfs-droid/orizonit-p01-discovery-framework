# ADR 0024 — First local operator Web screens

03/10/2026 (-03). **CANDIDATE**, browser LAB pending. The v0.6.11 API same-host
R1 was accepted from Bruno's two captures; its code remains byte-for-byte intact.

## Decision

Add a separate `P01_Operator_Web.py` entry point that reuses the qualified API
server, account policy, sessions, exact grants and canonical report service.
Expose only three fixed UTF-8 Web assets, loaded with size/path bounds before
listening. No general static directory, new DB query contract or dependency.

The Portuguese client provides local login/logout, manual assessment ID entry,
page size, historical summary, coverage and evaluation/provenance details.
Continuation retains the assessment, limit, cursor and scope SHA from the
previous response. A 409 or invalid fence clears the report and requires a new
first-page query. Completed lifecycle never closes historical findings.

Browser bearer state stays in a closure in memory: no cookies, local/session
storage, IndexedDB or URL tokens. Password input clears before the login request
finishes. Logout clears displayed data immediately and attempts server revocation;
failed revocation is reported accurately, with the existing 15-minute server TTL.
Expiry, 401, page exit and history restoration clear client state. Request
generation checks prevent late responses from repopulating a logged-out page.

All report/account values use text DOM nodes, never HTML interpretation. CSP
allows only same-origin external script/style and fetch, with no inline/eval,
frames, base URI or form navigation. Assets/API are no-store. The Web listener
checks Host and Origin/Fetch Metadata before delegating to authentication.
Direct numeric IPv4 URLs are supported; localhost is allowed on loopback for an
SSH tunnel. A tunnel uses the same port at both ends. DNS/reverse-proxy origins
need a future explicit configuration; forwarded headers do not establish identity.

HTTP remains loopback-only; remote listener still requires the existing TLS
contract. Initial browser LAB uses an SSH tunnel to the temporary Rocky listener,
with no service install, firewall opening, migration or collection.

## Verification and limits

Real HTTP tests cover asset confinement/CSP, cross-origin and rebinding denial,
login/report/logout and exact grants. Event-level Node tests cover text rendering,
fence/navigation, expiry and late responses; this harness does not render a browser.
An isolated Playwright/Chromium CI workflow exercises the actual screens at
desktop/mobile sizes, including text injection, fenced navigation, no persistent
storage/cookies, denied scope and logout/reload. Tooling is a CI dependency only,
following [Playwright's CI guidance](https://playwright.dev/docs/ci); no browser
test credential is a product account. Screenshots use a synthetic fixture, not LAB data.
PostgreSQL 16/17 CI exercises canonical equality and all 14 table invariants via
the Web listener. A temporary manual LAB launcher checks DB invariance on exit,
removes synthetic account files and labels browser acceptance as a separate gate.

UI rendering/accessibility and the Windows-to-Rocky tunnel need Bruno's browser
validation. AD/SSO, account management, assessment listing, imports/scan actions,
file download, MFA, public hardening and production remain later gates.

[API decision](ADR_0023_Local_Operator_API_v0.6.11.md) ·
[API R1 acceptance](validation/LOCAL_OPERATOR_P01LAB_R1_v0.6.11.md) ·
[Browser R1](LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md).
