# ADR 0022 — Explicit node authorization per assessment

Status: CANDIDATE, v0.6.10. Engineering increment; LAB acceptance is separate.

## Context

Remote ingestion already authenticates Discovery Nodes with mTLS and checks the
certificate/header/bundle node identity. Certificate possession alone does not
currently limit which assessment that node may import. Bundle lookup checks node
ownership but has no assessment grant. Human API/Web authentication remains a
separate boundary; node certificates must not become operator credentials.

## Decision

Add an explicit, startup-loaded `--node-policy` to the existing mTLS ingestion
server. A versioned policy grants `bundle:ingest` and/or `bundle:read` to an exact
node/assessment pair. Missing nodes, assessments or permissions deny access.
No wildcard, inherited permission or admin override exists. Node matching follows
the existing case-insensitive certificate binding; assessment IDs are exact.

Validate the complete bounded policy before store/server startup. Invalid,
duplicate, unknown or malformed policy entries abort startup, without returning
their contents. Retain an immutable in-memory snapshot. A policy change, including
revocation, requires a controlled server restart; this is not live revocation.

Check node membership before consuming/staging upload bytes. After the common
bundle validator authenticates the manifest contents, check the ingest grant
before the importer or optional metadata index. Lookup checks membership before
store search and read permission on the receipt assessment before returning any
receipt or invoking the index. Rejected early HTTP requests close the connection
so unread bytes cannot become another request. Error responses expose fixed codes.

The flag is opt-in for compatibility with the qualified v0.5d transport. Without
it, the existing transport/ownership gates remain; `/healthz` explicitly reports
`transport_only`. That legacy mode is not assessment authorization. New deployments
that need assessment isolation must enable the policy. Policy use with localhost
transport is rejected because it has no authenticated certificate principal.

## Scope and consequences

- Keep canonical offline ingestion and remote upload semantics; no new importer.
- No database migration, tenant model, collection permission or remote commands.
- Local CLI/offline import remains under host operator control.
- Do not alter an installed agent, service or the approved Rocky recovery fixture.
- Reader/ingester grants are independent; a node can be write-only or read-only.
- Human authentication, OIDC/Entra integration, operator RBAC, audit persistence,
  enrollment, rate limiting and live revocation need their own increments.
- Functional exporter acceptance and technical Markdown content/GFM review
  passed in synthetic Rocky R1; neither qualifies node authorization on the host.

## Qualification

Test malformed/duplicate policies, exact scope and immutable snapshots; denied
nodes before staging; denied assessments/operations before importer/index; real
synthetic bundle import/replay/lookup; HTTP rejection/connection hygiene and mTLS
certificate/header/policy integration. Run existing ingestion and full Python
regressions. Do not claim a new real-host or production acceptance from CI.
