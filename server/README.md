# Cancã — local operator Web v0.6.12 / report API v0.6.11

**Web R1 LAB VALIDATED; wider release CANDIDATE.** Fifteen Windows/Rocky captures
demonstrate local login/report pages, denied scope, logout/empty login, reduced
desktop window and two launcher STOP PASS results with 14-table invariance/cleanup.
[Acceptance and limits](../docs/validation/LOCAL_OPERATOR_WEB_P01LAB_R1_v0.6.12.md).
API v0.6.11 same-host synthetic R1 is
[LAB VALIDATED](../docs/validation/LOCAL_OPERATOR_P01LAB_R1_v0.6.11.md).
Separate server boundary for Web/API operator access.
Local login first, as selected by Bruno; optional AD/SSO integration follows.
The optional Web entry point provides the first Portuguese login/report screens
using the qualified backend, whose files remain unchanged.

## Who authenticates where?

| Use | Identity |
| --- | --- |
| Run portable discovery/collection | No Cancã login; existing host permissions and authorized collection scope |
| Authenticate to a target | Existing scoped target credentials/Secret Provider |
| Connected upload and receipt lookup | Discovery Node certificate and node grants |
| Read reports through the operator server | Local operator session and exact assessment grant |

Portable/offline CLI behavior, target credential storage and node transport are
unchanged. Human accounts do not grant collection permission or target access.
Future AD integration is optional at the server, with its own group/grant mapping.

## Bootstrap in a controlled new deployment

Python 3.12+ with OpenSSL scrypt; PostgreSQL driver from
`persistence/requirements-postgres.txt` for report reads. No new dependency.
Create a private configuration directory under administrator control. POSIX
account files must be regular, mode 0600 and owned by the current user or root;
directory aliases and final symlinks are rejected where supported. On Windows,
configure restrictive ACLs explicitly; POSIX mode is not an ACL qualification.

```sh
python server/P01_Operator_Auth.py --policy /etc/canca/operator-accounts.json --operator-id OP-01 --username reader --assessment-id LAB-001
```

The interactive terminal asks for a 15–256 character password twice. It writes
only salted scrypt hashes and non-secret IDs/grants; no default credentials or
password arguments. It refuses to overwrite an existing file. Account policy
is limited to 64 KiB/128 accounts/128 grants per account. Only
`assessment:read` exists. Assessment IDs are exact and case-sensitive; usernames
are ASCII IDs compared case-insensitively. There is no wildcard or implicit admin.

Configure PostgreSQL through the existing PG environment/PGPASSFILE contract,
using a dedicated SELECT-only reader on the report tables. Then:

```sh
python server/P01_Operator_API.py --accounts /etc/canca/operator-accounts.json --host 127.0.0.1 --port 8878
```

For the Web screens, run the separate entry point with the same options:

```sh
python server/P01_Operator_Web.py --accounts /etc/canca/operator-accounts.json --host 127.0.0.1 --port 8878
```

Open `http://127.0.0.1:8878/` on the same host, or via an SSH tunnel on the same
local/remote port. Enter a local operator account and the exact assessment ID;
there is no assessment enumeration. Reports show historical results, coverage
and source provenance. Completed lifecycle does not mean findings remediated.
Changing scope clears the page; query the first page again. Browser tokens are
kept only in memory; reload requires login. Sair clears data immediately and
revokes the session; a failed revocation is displayed explicitly, with server TTL.

HTTP is permitted only on 127.0.0.1 for same-host LAB clients. Remote IPv4 binds
require both `--tls-cert` and `--tls-key`, a trusted hostname/certificate and
restricted network access. TLS 1.2+; IPv6 and reverse-proxy forwarded identities
are not supported in this increment. The node ingestion listener stays separate.
The Web listener accepts direct numeric IPv4 URLs, plus localhost on loopback.
Host port must match the listener port; arbitrary DNS names/proxy origins are
not configured. Cross-origin and same-site requests from a different origin fail.
The standalone v0.6.11 API contract remains unchanged.
Startup/health do not connect to PostgreSQL or attest database readiness.

## HTTP contract

| Method/path | Contract |
| --- | --- |
| GET `/healthz` | Fixed authentication/version mode; no accounts, grants or DB information |
| GET `/`, `/assets/operator.css`, `/assets/operator.js` | Web entry point only; fixed public login shell/assets, no report data |
| POST `/api/v1/operator/session` | Strict `application/json` object with `username`/`password`; 201 returns an opaque bearer token |
| GET `/api/v1/assessments/{id}/report` | Requires `Authorization: Bearer <token>` and exact read grant; canonical report page |
| DELETE `/api/v1/operator/session` | Revokes that bearer token immediately |

Keep tokens in client process memory; do not put them in URLs, command arguments,
browser persistent storage, evidence or logs. Responses are no-store, with no
cookies or CORS allowance. Login body maximum 4 KiB; requests close after each
response. Duplicate security headers, transfer encoding and Expect are rejected.

Report query parameters: `limit` 1–100, `after_analysis_id`, `after_ordinal` and
`expected_scope_sha256`, with the existing mandatory fence for continuation.
Unknown/duplicate parameters fail. Missing/expired sessions return 401; absent
grant returns 403 before DB connection; malformed queries return 400; scope
change returns 409; authorized missing assessment returns 404. Backend failures
return fixed codes, never DSNs, paths or raw exceptions. Historical findings and
lifecycle semantics match the canonical report; no store reads/reanalysis.

Sessions expire absolutely after 15 minutes; at most 128 active sessions.
Five failed logins per account/anonymous bucket impose a five-minute window;
all logins share a 20-attempt/minute budget. At most eight workers and one password
verification at a time bound process work. These limits can deny legitimate
access under abuse; they are controlled Alpha limits, not distributed DoS protection.

## Administrative changes and limits

Account/grant changes require a controlled restart and invalidate all sessions.
Stop admitting traffic and wait for active requests to finish before restart.
No signup, password recovery, account mutation endpoint, MFA, persistent audit,
HA sessions, tenancy or SSO yet. Breached-password screening/public login
hardening remain release gates. No assessment listing, import, lifecycle update,
file download, server-side scan or commercial entitlement in this API.

Do not deploy automatically to the approved Rocky service or expose a LAB HTTP
listener remotely. The [short R1](../docs/LAB_LOCAL_OPERATOR_R1_v0.6.11.md) starts
a temporary loopback server, reuses the approved persistence modules, performs
only SELECTs and removes synthetic credentials after the check.
That API gate and the short [browser R1](../docs/LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md)
are approved. The historical browser procedure
uses a separate temporary Web listener, private synthetic account and 14-table
comparison on exit. It does not repeat restore/lifecycle/export qualification.
Do not repeat either accepted R1; see the evidence record for the remaining wider gates.

[ADR 0023](../docs/ADR_0023_Local_Operator_API_v0.6.11.md) ·
[ADR 0024](../docs/ADR_0024_Local_Operator_Web_v0.6.12.md).
