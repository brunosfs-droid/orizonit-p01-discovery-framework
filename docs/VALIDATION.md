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

## Connected Discovery Node Upload v0.5d.0

Candidate acceptance:

- remote transport uses HTTPS only;
- server mTLS mode fails closed without server cert, key and trusted client CA;
- TLS minimum is 1.2;
- valid client certificate is required before HTTP ingestion;
- `X-P01-Node-ID` must match authenticated certificate identity;
- validated bundle `node_id` must match authenticated node identity;
- status lookup is scoped to the authenticated node;
- Discovery Node validates server certificate and hostname;
- client private key remains local and is never stored in bundle/upload receipt;
- valid upload preserves the same v0.5b/v0.5c semantic result;
- repeated valid upload remains idempotent;
- missing/untrusted client certificate is rejected at TLS handshake;
- node header/certificate mismatch is rejected with HTTP 403;
- retries are bounded and limited to transport failures only;
- no server-initiated discovery, customer authentication or arbitrary command execution.


## Connected Discovery Node v0.5d

LAB VALIDATED.

Local mTLS R1:
- valid upload -> HTTP 201 / imported;
- repeat upload -> HTTP 200 / already_imported;
- semantic_match=true;
- missing client certificate rejected during TLS;
- valid certificate + forged X-P01-Node-ID rejected with HTTP 403;
- untrusted client certificate rejected before HTTP.

Separate-host R2:
- Discovery Node P01-MGMT01 / 192.168.100.20;
- Central Ingestion Server P01-LNX-RKY01 / 192.168.100.50;
- remote URL https://P01-LNX-RKY01.p01.lab.test:8443;
- first remote upload -> 201/imported;
- second remote upload -> 200/already_imported;
- authenticated_node_id=P01-MGMT01;
- server observed source 192.168.100.20;
- semantic_match=true;
- same .p01bundle and same server-side ingestion/Asset Resolver pipeline reused.


## Portable Discovery Node Runtime v0.5e.0

Candidate acceptance:

- same entry point runs on Windows and Linux with Python 3.10+;
- `doctor` performs no customer-network scan, secret resolution or authentication;
- `init` creates an isolated assessment/run workspace;
- runtime config and state each have SHA256 sidecars;
- state/config contain no plaintext password, Secret Provider locator or private-key material;
- `status` detects state-sidecar tampering;
- existing evidence can be wrapped into the validated v0.5a `.p01bundle`;
- source evidence sidecars are required by default;
- completed bundle export is not silently rebuilt;
- completed connected upload is not silently repeated;
- `--force-rebuild` and `--force-resend` are explicit operator actions;
- client private-key path is invocation-only and is not persisted in runtime state;
- connected upload continues to use the v0.5d HTTPS/mTLS uploader and same server ingestion pipeline;
- Network Discovery, Planner, Executor and Asset Resolver remain `external_required` in v0.5e.0 and are not run automatically.

Initial P01LAB gate: doctor -> init -> status -> export existing validated evidence -> status -> upload to the existing Rocky server -> status, then rerun status/upload to prove resume protection.


## Portable Discovery Node v0.5e.1

Candidate acceptance:

- `run` refuses active discovery without `--ack-authorized-scan`;
- effective target IPs must all fall inside Assessment Manifest `authorized_scopes`;
- manifest `exclude_scopes` are always honored;
- managed discovery writes JSON + SHA256 inside the workspace;
- state transitions `network_discovery: pending -> running -> completed`;
- no credential resolution or authentication occurs;
- repeat `run` after successful completion returns `already_complete` and performs zero network activity;
- explicit force-rescan is rejected if downstream completed steps would become stale;
- P01LAB acceptance: authorized `192.168.100.0/24` scan completes and second identical runtime command performs no second scan.


## Portable Discovery Node Runtime v0.5e.1

LAB VALIDATED on P01-MGMT01 using workspace `P01LAB-RUNTIME-R2`.

Acceptance evidence:
- workspace initialization and SHA256-protected state succeeded;
- active discovery without `--ack-authorized-scan` was rejected before scanning;
- effective scope outside the Assessment Manifest authorization was rejected;
- authorized `192.168.100.0/24` discovery completed and produced workspace-owned JSON + SHA256;
- 4 hosts were discovered in the observed LAB run;
- runtime state advanced to `network_discovery: completed`;
- a repeated `run` returned `already_complete` with no second network activity and no authentication attempts.

## Portable Discovery Node Runtime v0.5e.2

Candidate acceptance:
- a completed Network Discovery workspace advances to managed Credential Planner on the next `run`;
- planner input Network Discovery must exist and match the SHA256 recorded in runtime state;
- Assessment Manifest and Credential Profiles references must exist;
- planner output JSON + SHA256 are stored under the workspace;
- planner output/state persist no secret values or Secret Provider locators;
- planning performs no network activity, secret resolution or authentication;
- repeated planning returns `already_complete` and does not rebuild the plan;
- existing v0.5e.1 workspaces with `credential_plan: external_required` are adopted safely;
- force-replan is rejected when completed downstream artifacts would become stale.


## Portable Discovery Node Runtime v0.5e.2 — P01LAB

LAB VALIDATED on P01-MGMT01 using workspace `P01LAB-RUNTIME-R2`.

Acceptance evidence:
- existing v0.5e.1 state with `credential_plan: external_required` was adopted in place;
- managed planner processed 4 assets and produced Credential Plan JSON + SHA256;
- planning reported zero network activity, secret resolution and authentication;
- runtime state advanced to `credential_plan: completed`;
- repeated planner run returned `already_complete`.

The observed `adapter_candidates=0` was specific to that isolated v0.4b.6 profile file and was not a planner-runtime failure.

## Portable Discovery Node Runtime v0.5e.3 — P01LAB

LAB VALIDATED on P01-MGMT01 using fresh workspace `P01LAB-RUNTIME-R3`.

Acceptance evidence:
- managed Network Discovery found 5 hosts;
- managed Credential Planner produced 4 adapter candidates from 5 assets;
- Executor dry-run produced 4 actions and 4 ready actions;
- Credentialed Job JSON + SHA256 were written under `evidence\credentialed_execution`;
- runtime reported zero network activity, secret resolution and authentication during dry-run;
- state advanced to `credentialed_execution: preview_completed`;
- repeated dry-run returned `already_complete` without rebuilding or authenticating.

## Portable Discovery Node Runtime v0.5e.3.1

Candidate acceptance:
- AUTH-only live execution is available only after a validated Executor dry-run preview;
- live execution requires explicit `--execute --auth-only --ack-authorized-access`;
- FULL enrichment is rejected in this increment;
- Credential Plan, preview and Credential Profiles hashes are revalidated before authentication;
- executor remains sequential with concurrency 1 and keeps shared-credential failure budgets/circuit breaker;
- AUTH-only job and per-target evidence require JSON + SHA256 integrity;
- evidence/state must contain no plaintext credentials or Secret Provider locators;
- successful live run advances to `credentialed_execution: auth_validated`;
- repeated AUTH-only run returns `already_complete` and performs zero additional authentication;
- failed/partial AUTH execution cannot be retried silently; explicit `--force-auth-retry` plus authorization acknowledgement is required.


## Portable Discovery Node Runtime v0.5e.3.1 — P01LAB

LAB VALIDATED on P01-MGMT01 using workspace `P01LAB-RUNTIME-R3`.

Acceptance evidence:
- state resumed from `credentialed_execution: preview_completed`;
- AUTH-only without `--ack-authorized-access` was rejected before authentication;
- authorized AUTH-only execution completed 4 of 4 planned actions;
- authentication successes = 4, failures = 0, open credential circuits = 0;
- aggregate AUTH job JSON/SHA256 and four per-target JSON/SHA256 pairs were generated;
- live run correctly reported network activity, secret resolution and authentication attempts;
- state advanced to `credentialed_execution: auth_validated`;
- repeated AUTH-only invocation returned `already_complete` with zero additional network activity, secret resolution or authentication.

## Portable Discovery Node Runtime v0.5e.3.2

Candidate acceptance:
- FULL enrichment is available only after validated AUTH-only execution;
- live FULL requires explicit `--execute --full-enrichment --ack-authorized-access`;
- Credential Plan, dry-run preview, AUTH job and live Credential Profiles are hash-bound and revalidated before execution;
- executor runs `execute=true`, `auth_only=false`, `concurrency=1`;
- shared-credential failure budgets/circuit breaker remain active;
- aggregate FULL job and every completed target evidence file require JSON + SHA256 integrity;
- no plaintext credentials or Secret Provider locators may be persisted;
- all planned actions must be ready/completed/collected with successful authentication for the stage to become `full_completed`;
- partial/failed FULL evidence is preserved but the stage becomes `failed` and requires explicit `--force-full-retry`;
- repeated successful FULL invocation returns `already_complete` and performs zero additional network/authentication activity;
- next action after `full_completed` is Asset Resolver.


## Portable Discovery Node Runtime v0.5e.3.2 — P01LAB

LAB VALIDATED on P01-MGMT01 using workspace `P01LAB-RUNTIME-R3`.

Acceptance evidence:
- state resumed from `credentialed_execution: auth_validated`;
- FULL execution without `--ack-authorized-access` was rejected before live collection;
- authorized FULL execution completed 4 of 4 planned actions;
- collected = 4, authentication successes = 4, failures = 0, open credential circuits = 0;
- aggregate EXEC-FULL JSON/SHA256 and four per-target FULL JSON/SHA256 pairs were generated;
- state advanced to `credentialed_execution: full_completed`;
- repeated FULL invocation returned `already_complete` with zero additional network activity, secret resolution or authentication.

## Portable Discovery Node Runtime v0.5e.4

Candidate acceptance:
- a `full_completed` workspace advances to managed Asset Resolver on a plain `run`;
- Network Discovery and aggregate FULL job must match hashes recorded in runtime state;
- only collected target evidence explicitly referenced by the aggregate FULL job is selected;
- every target must remain inside the workspace and pass SHA256 sidecar/in-job digest validation;
- AUTH-only target evidence is not selected as resolver input;
- Assessment Manifest is reused from the workspace source reference when present;
- resolver remains offline/read-only with zero network activity, secret resolution and authentication;
- resolver JSON + SHA256 are written under `resolved`;
- repeated resolve returns `already_complete` without a second resolver run;
- force-reresolve is rejected after completed Evidence Bundle or Upload;
- state advances to `asset_resolver: completed` and next action is Evidence Bundle export.
