# Cancã — local operator report API v0.6.11

**CANDIDATE.** Separate server boundary for the first Web/API operator access.
Local login first, as selected by Bruno; optional AD/SSO integration follows.
This increment provides the backend API. The Web login/report screens follow
qualification of this boundary.

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

HTTP is permitted only on 127.0.0.1 for same-host LAB clients. Remote IPv4 binds
require both `--tls-cert` and `--tls-key`, a trusted hostname/certificate and
restricted network access. TLS 1.2+; IPv6 and reverse-proxy forwarded identities
are not supported in this increment. The node ingestion listener stays separate.
Startup/health do not connect to PostgreSQL or attest database readiness.

## HTTP contract

| Method/path | Contract |
| --- | --- |
| GET `/healthz` | Fixed authentication/version mode; no accounts, grants or DB information |
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

[ADR 0023](../docs/ADR_0023_Local_Operator_API_v0.6.11.md).
