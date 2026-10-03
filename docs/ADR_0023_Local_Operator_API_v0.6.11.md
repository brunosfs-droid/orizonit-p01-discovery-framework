# ADR 0023 — Local operators and read-only assessment API

02/10/2026 (-03). Local-first login approved by Bruno; implementation CANDIDATE.

## Decision

Community starts with independent local operator accounts. Future AD/SSO/Entra
adapters must yield an operator principal, without treating node certificates,
database users, collector credentials or client-supplied IDs as human login.

The portable collector runs without Cancã operator login. Its existing target
credential profiles/Secret Providers remain scoped collection inputs. Offline
work stays independent of server availability. Connected node mTLS authenticates
upload/receipt access only; no new human login is added to portable collection.
Optional AD integration belongs to the server operator boundary.

Add a separate operator server and private, bounded startup account policy.
Initial grants allow only exact `assessment:read` scopes. No admin wildcard,
signup, lifecycle mutation, import, export-file download or listing of all
assessments. Delegate report pages to the existing read-only canonical query.
Authenticate and check the grant before opening a database connection; retain
the existing cursor/fence and explicit historical findings semantics.

Use stdlib scrypt N=32768/r=8/p=3, random 16-byte salts, 32-byte hashes and fixed
parameters. This is an OWASP-listed 32 MiB setting, appropriate for a bounded
LAB service without a new authentication dependency. Passwords are 15–256
Unicode characters and at most 1024 UTF-8 bytes, without normalization or silent
truncation. An interactive CLI creates one private account file exclusively;
no password argument, default account or password echo.

Sessions are random 256-bit opaque bearer tokens, held as SHA256 digests in a
bounded process-local map, with absolute 15-minute expiry and explicit logout.
No tokens in URLs/cookies/logs; no refresh or persistence. Editing the immutable
policy requires a controlled restart, which revokes all sessions. Per-account
failure limits, a global attempt window and bounded workers limit login work.

HTTP is allowed only on 127.0.0.1 for a controlled same-host LAB. Remote access
requires TLS with a server certificate; node mTLS remains on its existing port.
No CORS allowance, forwarded-principal trust or query-token authentication.
Strict JSON/framing limits and fixed errors protect the new boundary. HTTP logs
contain no request paths, credentials or tokens. Responses are no-store.

## Limits and qualification

This is a controlled Product Alpha API, not a production/public login service.
No Web UI, MFA, recovery email, breached-password screening, HA sessions,
operator audit persistence, tenancy, account management API or SSO yet.
Administrative account file changes are outside the HTTP surface. Safety,
permission and capacity limits apply to all editions; no commercial quota.

Test actual password hashing, disabled/unknown/wrong login, throttle, token
expiry/logout, strict policy, cross-assessment denial before DB, malformed
HTTP/duplicate headers, and real HTTP sessions. PostgreSQL 16/17 CI verifies
canonical report equivalence, fenced pages and preserved database contents.
Real-host acceptance stays separate; no deployment or migration is automatic.

References: [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[OWASP authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html),
[Python hashlib](https://docs.python.org/3.12/library/hashlib.html).
