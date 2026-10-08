# Cancã — local operator Web v0.6.17 / report API v0.6.11

**Web v0.6.17 executive preview CANDIDATE; Web v0.6.12 R1 LAB VALIDATED.**
[Executive preview and limits](../docs/OPERATOR_WEB_PREVIEW_v0.6.17.md).
An explicit action shows complete historical coverage, recorded severities and
ten recommendation groups per page using the displayed report's scope. Preview
and both ZIP downloads share one collection slot; their previous formats stay pinned.
[Own-grant selector and limits](../docs/OPERATOR_ASSESSMENT_SELECTION_v0.6.16.md).
The Web directory reads the current session's startup-policy IDs without opening
PostgreSQL; choose an ID then explicitly query. It does not establish existence.
[Executive download and shared limits](../docs/OPERATOR_WEB_EXECUTIVE_v0.6.15.md).
Technical download retains content/delivery 0.6.9/0.6.13. Manual LAB download
gates remain deferred; historical guides keep their qualified Git pins.
Fifteen Windows/Rocky captures
demonstrate local login/report pages, denied scope, logout/empty login, reduced
desktop window and two launcher STOP PASS results with 14-table invariance/cleanup.
[Acceptance and limits](../docs/validation/LOCAL_OPERATOR_WEB_P01LAB_R1_v0.6.12.md).
API v0.6.11 same-host synthetic R1 is
[LAB VALIDATED](../docs/validation/LOCAL_OPERATOR_P01LAB_R1_v0.6.11.md).
Separate server boundary for Web/API operator access.
Local login first, as selected by Bruno; optional AD/SSO integration follows.
The optional Web entry point provides the first Portuguese login/report screens
using the existing session/report contracts. v0.6.16 adds a session-checked grant
accessor to LocalAuth; the standalone API routes/policy format remain unchanged.
Earlier qualified sources are preserved at their Git pins.

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
local/remote port. Enter a local operator account, choose an ID from its own grants
or type an exact ID, then explicitly query. The grant list does not check report
existence. Reports show historical results, coverage
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
| GET `/api/v1/operator/assessments` | Web v0.6.16 only; own sorted policy grant IDs, no query/body/SQL/existence check |
| GET `/api/v1/assessments/{id}/report` | Requires `Authorization: Bearer <token>` and exact read grant; canonical report page |
| GET `/api/v1/assessments/{id}/report/executive` | Web only; mandatory displayed scope fence; bounded preview with ten recommendation groups per page |
| GET `/api/v1/assessments/{id}/report/export` | Web only; exact read grant and mandatory scope fence; complete ZIP |
| GET `/api/v1/assessments/{id}/report/executive/export` | Web only; same authorization/fence and shared export slot; executive ZIP |
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

Web v0.6.13 adds **Baixar relatório completo (ZIP)** to a loaded report. It includes
all evaluations in JSON/Markdown and a hash manifest, regardless of the displayed
page size. Nothing is written on the server. One export at a time, 32 MiB archive
limit and cooperative 60-second deadline bound this operation. A saved download
remains on the operator's computer after logout. The browser verifies archive
SHA256/scope/length and suppresses late downloads after logout/expiry.
[Download contract and limits](../docs/OPERATOR_WEB_EXPORT_v0.6.13.md).

Sessions expire absolutely after 15 minutes; at most 128 active sessions.
Five failed logins per account/anonymous bucket impose a five-minute window;
all logins share a 20-attempt/minute budget. At most eight workers and one password
verification at a time bound process work. These limits can deny legitimate
access under abuse; they are controlled Alpha limits, not distributed DoS protection.

## Administrative changes and limits

The [optional private audit v0.6.19](../docs/OPERATOR_SERVER_AUDIT_v0.6.19.md)
records handled requests into one new private JSONL file per listener when
`--audit-file` is specified. Fixed operation labels, authenticated operator IDs
and authorized assessment IDs exclude submitted secrets/URLs/report content.
An 8 MiB budget reserves request completions; failed admission returns 503 before
new authentication or backend work. Audit remains off by default. New filename,
private directory/Windows ACLs and controlled restart are deployment requirements;
no live LAB configuration change is requested.

The [offline audit review v0.6.20](../docs/OPERATOR_AUDIT_CHECK_v0.6.20.md) reads
a stable private file and distinguishes closed structure (exit 0) from valid
open/partial prefixes (exit 3) and invalid input (exit 2). Fixed counts and the
full-file SHA256 omit private IDs/lines; it never repairs or changes the log.
It does not attest authorship, actual grant enforcement or durable fsync.

The [offline administrator CLI v0.6.18](../docs/OPERATOR_ACCOUNTS_v0.6.18.md)
inspects a private policy and creates a distinct revision for add, exact grant
replacement, enable/disable or password rotation. Each change requires the source
file SHA256 and a new private output name; passwords use hidden terminal prompts.
It does not reload a running listener or revoke its live tokens. Review the
revision, then use its file only through a controlled restart. Policy v1 and
Web/API authentication contracts remain unchanged. No real account/LAB change
is requested by this CANDIDATE increment.

Account/grant changes require a controlled restart and invalidate all sessions.
Stop admitting traffic and wait for active requests to finish before restart.
No signup, password recovery, account mutation endpoint, MFA, immutable remote audit,
HA sessions, tenancy or SSO yet. Breached-password screening/public login
hardening remain release gates. No PostgreSQL assessment inventory, import,
lifecycle update, server-side scan or commercial entitlement. The standalone API
does not offer the Web policy directory, executive preview or report-download routes.

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

## Workspace API v0.6.26 opt-in

[Contrato](../docs/WORKSPACE_API_v0.6.26.md): listener separado em schema7,
LocalAuth + binding operador/role SQL privado e conexão por request. Operações
exigem workspace/generation; grants atuais no banco. Não substituir listener
legado/schema4; CLI e limites no contrato. Migração/UI/Mapper ainda pendentes.

## Workspace Legacy v0.6.28 opt-in

[Contrato](../docs/WORKSPACE_LEGACY_v0.6.28.md): listener atual exige schema9,
preservando versões7/8 nos commits qualificados. Acrescenta rotas legacy/preview,
legacy/apply e legacy/{bundle_id}/report com geração/revisão/grants e jobs do
coordenador. LegacySources é mapping privado por assessment do store original
somente leitura; requests não recebem paths ou roles. Audit HTTP workspace e
recovery operacional continuam pendentes.
