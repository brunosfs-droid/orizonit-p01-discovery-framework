# Validation Plan

## General acceptance

Every component must prove:

- parseable output;
- SHA-256 match where generated;
- explicit errors/limitations/warnings;
- no unintended configuration changes;
- stable field semantics;
- no secrets in output;
- reproducible test evidence archived outside Git.

## Windows / AD collector

Validate at minimum:

| Scenario | Expected |
|---|---|
| Domain member, standard user | collection completes with privilege limitations |
| Domain member, local admin | expanded local visibility |
| AD module available | domain inventory succeeds |
| AD/GPO skipped | local collection continues |
| SMB broad share + broad NTFS | confirmed broad write |
| SMB broad share + restrictive NTFS | not confirmed broad write |
| IIS FTP plaintext allowed | NET-FTP-001 evidence available |
| Secure channel healthy/broken | status reported without repair action |

### AD stale

Do **not** attempt to validate by directly editing `lastLogonTimestamp` or `lastLogon`. These are system-managed logon attributes.

Use:

1. never-logged-on test objects;
2. reduced `-InactiveThresholdDays` for lab;
3. synthetic/unit tests with controlled dates;
4. production threshold normally set to 90 days.

See `docs/validation/AD_STALE_v0.3.md`.

## Linux collector

Validate Ubuntu and Rocky with:

- root and non-root contexts;
- SSH effective config;
- FTP plaintext/unknown states;
- Samba confirmed/potential/read-only permission cases;
- pwquality/PAM;
- NTP;
- systemd failed services;
- JSON + SHA256.

## Analyzer

For every ruleset version:

- run against previous Golden Dataset;
- require `ingestion_error_count = 0`;
- require `rule_error_count = 0`;
- confirm positive and negative fixtures;
- confirm no duplicate findings from lower-coverage collectors.

## Network Discovery v0.4a

### Unit
- CIDR/range expansion;
- exclusions;
- safe/standard port profiles;
- basic classification.

### Self-test
- loopback scan;
- parseable JSON;
- valid SHA256;
- no credential attempts.

### Home/LAB
Compare discovered assets to an independently known inventory such as router/AP client list.

Record:

- effective scope;
- duration;
- known devices;
- discovered devices;
- missed devices;
- false positives;
- classification confidence;
- ports/fingerprints;
- SSDP enrichment.

Absence of response is not proof of absence. Mobile/sleeping devices and routed networks require special interpretation.


## SSH Credentialed Enrichment v0.4b.2.1

Validated through P01-MGMT01 Discovery Node against controlled Ubuntu and Rocky targets:

- AUTH-only succeeded with exactly one matching /32 profile per host;
- one attempt, zero same-profile retries;
- secret values were not persisted to output;
- full enrichment returned hostname, kernel/OS, IPv4 interfaces, routes and IPv4 forwarding;
- SSH exec capability probe succeeded;
- candidate network 192.168.100.0/24 was emitted with auto-scan disabled;
- JSON/SHA256 evidence matched;
- restricted appliance behavior is classified separately as authenticated_no_exec_output.

Windows 11 was intentionally powered off during the discovery-node baseline and will be enabled for the future WinRM/WMI validation.



## Context-aware Credential Resolver v0.4b.3

Validated against the P01LAB Network Discovery dataset:
- 4 assets processed;
- Windows hosts with WinRM received no profile before WinRM credentials existed;
- Ubuntu received only its own /32 SSH profile;
- Rocky received only its own /32 SSH profile;
- device type, OS family, service and confidence selectors matched;
- planner resolved no secrets and performed no authentication;
- JSON/SHA256 evidence matched.

Windows workstation safety gates are also validated:
- Windows/domain context with no WinRM detected -> no plan;
- WinRM detected but no eligible profile -> no plan;
- both cases resolve no secrets and make no authentication attempts.

The declared `failure_budget_per_job` is not yet considered runtime-validated because the multi-target executor is not implemented.

## WinRM Credentialed Enrichment v0.4b.4

Candidate acceptance:
- profile/context match before secret resolution;
- auth-only first;
- one bounded attempt and zero same-profile retries;
- secrets absent from output;
- fixed read-only PowerShell/CIM payload;
- identity/domain/OS/network/DNS/firewall/hotfixes;
- candidate networks with auto-scan disabled;
- no automatic WinRM enablement or configuration changes.

## Multi-target Credentialed Executor v0.4b.5

Validated AUTH-only through P01-MGMT01 against five controlled P01LAB targets:

- P01-DC01 via WinRM/domain profile;
- P01-MGMT01 via WinRM/local profile;
- P01-W11-01 via WinRM/domain workstation profile;
- Ubuntu via SSH;
- Rocky via SSH;
- execution remained sequential with concurrency 1;
- 5/5 authentication successes, zero failures, zero skips and zero open circuits;
- DC01 and W11 shared one hashed credential identity and accumulated two successes;
- every target JSON matched both its SHA256 sidecar and the digest recorded by the job;
- plan SHA256 was propagated to every target result;
- no secret values or secret references were persisted.

Full enrichment multi-target remains a separate acceptance gate.

## Read-only / non-destructive expectations

Collectors must not modify system configuration. Network Discovery is allowed to generate authorized ICMP/TCP/SSDP probe traffic but must not:

- exploit vulnerabilities;
- perform brute force;
- spray credentials;
- change services;
- install software on targets;
- create persistence.


## Multi-target Credentialed Executor v0.4b.5

Validated in P01LAB with five planned assets:

- dry-run: 5 actions ready, zero secret resolution and zero authentication;
- AUTH-only: 5/5 authentication success, zero skipped actions and zero open circuits;
- full enrichment: 5/5 authentication success and 5/5 collection success;
- SHA256 binding between Credential Plan, Job and per-target result evidence;
- shared domain identity recognized across DC01 and W11;
- execution remained sequential with concurrency=1;
- no pivoting and no dynamic-scope expansion.

This closes the current v0.4b SSH/WinRM orchestration baseline.

## Assessment Context & Credential Intake v0.4b.6

LAB VALIDATED. Acceptance:

- operator-declared domains/realms are stored as non-secret context;
- manifest validation rejects plaintext secret-like fields;
- declared realm candidates do not become effective realm evidence by declaration alone;
- an observed FQDN suffix matching a declared scoped AD domain may promote realm state to `observed`;
- `realm_evidence_min=observed` blocks a domain profile when only declared context exists;
- `realm_evidence_min=credentialed_confirmed` remains blocked until credentialed evidence exists;
- target class, protocol, realm kind, privilege class, purpose and scope remain independent policy dimensions;
- high-privilege identities require explicit acknowledgement, one attempt and failure budget 1;
- suspicious placeholder usernames are surfaced as warnings;
- conflicting realm-map and observed domain context blocks planning;
- rich v0.4b.6 profiles do not match when context is absent;
- runtime components consume persisted manifest/profile configuration rather than interactive prompts;
- Secret Provider remains the only location for secret values.

Runtime P01LAB evidence validated both sides: declared+observed namespace evidence produced an adapter candidate, while declared-only context with no compatible observed FQDN produced `not_planned`. Both paths resolved no secrets and attempted no authentication.

## Asset Resolver v0.4c.0

LAB VALIDATED. Acceptance:

- resolver is offline-only and performs zero network access/authentication/secret resolution;
- Network Discovery observations seed independent logical assets;
- IP alone never auto-merges;
- MAC alone does not pre-merge separate Network Discovery observations;
- strong identifier exact match may correlate;
- otherwise auto-merge requires namespace evidence plus network evidence;
- field-level provenance is preserved;
- medium-or-strong disagreements are recorded as conflicts;
- `observed` realm evidence is not treated as confirmed domain membership;
- credentialed Windows domain evidence may promote realm state to `credentialed_confirmed`;
- output contains no secret-provider reference or secret-like field;
- Network Discovery and credentialed evidence sidecars can be required and verified;
- real P01LAB R2 resolved five Network Discovery assets plus five FULL credentialed observations into exactly five logical assets, with zero unresolved, zero ambiguous correlations and zero conflicts.
- local authentication realm is preserved separately from canonical directory realm identity.

## Evidence Bundle v0.5a.0

Candidate acceptance:

- create a .p01bundle from existing immutable P01 evidence;
- optional input sidecar validation rejects missing or invalid evidence SHA256;
- bundle contains Network Discovery + credentialed FULL evidence + Assessment Manifest + Asset Resolver result;
- same bundle format is transport-agnostic for connected and offline modes;
- every payload is covered by SHA256 inventory;
- outer bundle SHA256 sidecar validates;
- tampered payload is rejected;
- duplicate ZIP entry, path traversal and symlink are rejected;
- Secret Provider references and secret-like JSON keys are rejected;
- bundle ID is stable for the same assessment/run/node/evidence inventory;
- validation performs no network access, authentication or secret resolution;
- real P01LAB gate should package 8 artifacts: 1 network + 5 credentialed + 1 manifest + 1 Asset Resolver.


## Central Ingestion API v0.5c.0

Candidate acceptance:

- default bind is loopback-only;
- non-loopback bind is rejected;
- POST accepts raw `.p01bundle` only;
- Content-Length is mandatory and bounded;
- X-P01-Bundle-SHA256 is mandatory and verified before import;
- caller-provided filesystem paths are not used;
- optional Idempotency-Key must equal validated bundle_id;
- the same v0.5b `import_bundle()` function performs ingestion;
- first P01LAB API upload returns `imported` and semantic_match=true;
- second identical upload returns `already_imported`;
- GET bundle status reports semantic equivalence without exposing raw evidence;
- no customer-network access, authentication, secret resolution or arbitrary payload execution;
- malformed/tampered/oversized uploads are rejected.


## Central Ingestion API v0.5c.0 — P01LAB runtime status

### P01LAB positive runtime status
- localhost API started on 127.0.0.1:8088;
- health endpoint returned HTTP 200;
- first upload returned imported / HTTP 201;
- repeat upload returned already_imported / HTTP 200;
- bundle status GET returned HTTP 200;
- semantic_match=true with equal edge/server semantic digests;
- non-loopback bind 0.0.0.0 rejected.

### Negative gates R2
- missing/malformed SHA256 -> HTTP 400: PASS;
- wrong SHA256 -> HTTP 422: PASS;
- tampered bundle with recomputed outer SHA -> HTTP 422: PASS;
- oversized request -> HTTP 413 before processing: PASS;
- non-loopback bind -> rejected: PASS.

The R2 server log exposed one HTTP connection-hygiene defect: pre-body 400/413 responses left request bytes unread on a persistent connection. v0.5c.1 closes the connection explicitly on pre-body rejection. Final P01LAB rerun passed: missing-SHA returned 400 with `Connection: close`; oversized returned 413; no follow-on `Bad request version` or `414 URI Too Long` was observed. **Status: LAB VALIDATED.**

See `docs/LAB_CENTRAL_INGESTION_NEGATIVE_v0.5c.md`.
