## Unreleased — Apache 2.0 and edition strategy

- Replace the current source license with Apache-2.0, preserve attribution in
  NOTICE and align contribution/governance/MVP/roadmap documentation.
- Record Community-first stable launch, future separately licensed commercial
  modules and official edition limits still to be specified.
- Approve staged server inventory/mapper/dependency work after 1.0.
- Preserve historical commits/releases and dependency license obligations.
- No executable, schema, database, quota, entitlement or billing change.

## v0.6.10 — Explicit node assessment authorization (CANDIDATE)

- Add optional startup-scoped `--node-policy` to the mTLS ingestion server.
- Grant independent ingest/read permissions for exact node/assessment pairs; missing grants deny.
- Block unknown nodes before staging, denied scope before importer/index, and denied reads before receipt/index output.
- Validate bounded policy files and duplicate/unknown fields before startup; immutable snapshot requires controlled restart for revocation.
- Preserve certificate/header/manifest binding, bundle ownership, canonical import/replay and legacy mode with explicit health status.
- Add synthetic mTLS/HTTP and real bundle boundary tests; no migration or operator/Web authentication.
- Accept v0.6.9 exporter R1 on Rocky from five operator captures and two identical Markdown attachments: corrected installation, two exports, hash/permission/count verification PASS, technical content/GFM review complete; no graphical renderer or production qualification.

## v0.6.1 — Opt-in API metadata indexing (CANDIDATE)

- Add --metadata-index postgres (default off); index only after canonical filesystem import publication.
- Keep HTTP import acknowledgment independent; expose indexed/already_indexed/pending/review_required separately.
- Revalidate source/identity before DB access and preserve existing mTLS ownership gates.
- Reconcile one reviewed import with the existing explicit index-import command; no migration, sweep or retry on startup.
- Clean canonical staging under the bundle lock to protect concurrent duplicate requests.
- Add real PostgreSQL CI for unavailable DB, transaction rollback, concurrent duplicates and process exit before/after DB commit.
- Update corporate artifact policy to OneDrive/SharePoint; Google Drive remains legacy during independent migration.

## v0.6.0 — PostgreSQL metadata foundation (CANDIDATE)

- Add explicit migrate/index-import/show-import CLI for existing validated filesystem imports.
- Bind receipt/hash/identity and a private bundle snapshot before any database connection.
- Store assessment/node/run/import/artifact metadata atomically with replay, conflict rejection and advisory locks.
- Track migration checksum; require verified remote TLS and fixed redacted errors.
- Add real PostgreSQL 16/17 CI for rollback, concurrency, indexing role permissions and readback.
- Start Product Alpha; PostgreSQL server LAB and backup/restore remain pending.
- Clarify scheduler R1 accepted, extended soak optional for this increment.

## [Unreleased]

## v0.5f.0 — Optional agent foundation (CANDIDATE)

- Wrap canonical v0.5e.6 runtime with doctor/status/run-once and policy validation.
- Versioned policy binds assessment/run/node identity; absent grants deny stages.
- No OS service or scheduler installed; optional interval descriptor is metadata.
- Share nonblocking Windows/Linux workspace lock with portable mutations.
- Fail closed on invalid policy, stale artifacts/config or interrupted checkpoints.
- Preserve completed-run resume; no automatic retry, rescan or reauthentication.
- Reject interactive providers for unattended AUTH/FULL; strict SSH host keys.
- Journal fixed status codes and policy SHA256, never secrets, transport or raw errors.
- Add Windows/Linux CI and P01LAB acceptance procedure; real LAB pending.


### Validated
- Portable runtime v0.5e.6 end-to-end P01LAB flow through mTLS upload: HTTP 201/imported, semantic match, authenticated node binding, receipt/state completion, zero-input no-second-upload resume and forced-resend transport gate.

## [Unreleased]

### Added
- Portable runtime v0.5e.6 zero-input safe resume for completed connected uploads: after the first explicit mTLS upload, `upload --workspace ...` returns `already_complete` without transport parameters or network activity.

### Validated
- Portable runtime v0.5e.5 workspace-driven bundle in P01LAB-RUNTIME-R3: 7 payload artifacts, 4 EXEC-FULL credentialed files, valid SHA256 inventory and no AUTH evidence mixing.

## [Unreleased]

### Added
- Portable runtime v0.5e.5 workspace-driven Evidence Bundle export: normal export derives Network, EXEC-FULL target set, Asset Resolver and Manifest from validated workspace state with no manual evidence paths.

### Validated
- Portable runtime v0.5e.4 Asset Resolver in P01LAB-RUNTIME-R3: 5 network assets + 4 credentialed observations -> 5 logical assets, 0 unresolved/ambiguous/conflicts, offline resume with no second resolve.

## [Unreleased]

### Added
- Portable runtime v0.5e.4 managed offline Asset Resolver after FULL credentialed enrichment, using workspace-bound Network Discovery + EXEC-FULL target evidence with SHA256 validation and resume protection.

### Validated
- Portable runtime v0.5e.3.2 FULL enrichment gate in P01LAB-RUNTIME-R3: acknowledgement enforcement, 4/4 completed and collected actions, 4 authentication successes, zero failures/circuits and no-second-full behavior.

## [Unreleased]

### Added
- Portable runtime v0.5e.3.2 managed FULL credentialed enrichment after validated AUTH-only execution, with explicit authorization acknowledgement, staged hash binding, per-target JSON/SHA256 evidence and no-silent-repeat protection.

### Changed
- AUTH-only runtime now fails closed on partial/failed target results and requires explicit retry rather than incorrectly promoting the stage.

### Validated
- Portable runtime v0.5e.3.1 AUTH-only gate in P01LAB-RUNTIME-R3: acknowledgement enforcement, 4/4 successful authentications, 0 failures/circuits, per-target evidence and resume with zero second authentication.

## [Unreleased]

### Added
- Portable runtime v0.5e.3.1 gated AUTH-only credentialed execution after a validated dry-run preview, with explicit authorization acknowledgement, plan/preview/profile integrity checks and no-silent-retry safeguards.

### Validated
- Portable runtime v0.5e.3 Executor dry-run in P01LAB-RUNTIME-R3: 5 assets discovered, 4 adapter candidates, 4 ready actions, JSON/SHA256 evidence and resume `already_complete`.

## [Unreleased]

### Added
- Portable runtime v0.5e.2 managed Credential Planner stage after Network Discovery, with workspace-owned plan JSON/SHA256, resume protection and zero-auth planning semantics.

### Validated
- Portable runtime v0.5e.1 Network Discovery gate in P01LAB, including explicit authorization acknowledgement, manifest scope enforcement and no-second-scan resume behavior.

# Changelog

## [0.5d.0-lab-validated] - 2026-09-30

### Validated
- local mTLS server/client authentication
- server certificate validation and client certificate trust enforcement
- node identity binding between certificate SAN, X-P01-Node-ID and bundle node_id
- missing/untrusted client certificates rejected before HTTP ingestion
- forged node header rejected with HTTP 403
- first connected upload -> 201/imported
- repeated upload -> 200/already_imported
- cross-host Windows Discovery Node -> Rocky Linux ingestion server over HTTPS/mTLS
- semantic_match=true using the same .p01bundle and server ingestion pipeline

### Next
- v0.5e portable Discovery Node runtime and unified operator workflow


All notable changes to the P01 Discovery Framework are documented here.

## [Unreleased]

### Planned
- Validate AD stale behavior with reduced-threshold lab and synthetic tests
- Credential Manager and credentialed enrichment (v0.4b)
- Asset Resolver / deduplication (v0.4c)
- Reporting Engine v0.1

## [0.5b.0-candidate] - 2026-09-30

### Added
- offline `.p01bundle` import into a server/local evidence store
- validate-before-materialize flow
- safe manual archive materialization without `extractall`
- immutable raw bundle preservation
- deterministic import location by assessment + bundle ID
- import receipt JSON + SHA256
- idempotent repeated import handling
- optional server-side Asset Resolver replay using only imported evidence
- semantic edge/server Asset Resolver comparison

### Security
- payload files are never executed
- no network access, authentication or secret resolution during import/reprocessing
- outer bundle SHA256 can be mandatory for offline transfer
- bundle ID collision with different bytes is rejected

### Tests
- server-side semantic replay match
- idempotent second import
- required outer sidecar
- raw bundle preservation

### Next
- validate P01LAB-BUNDLE-R1 as the first real offline import

## [0.5a.0-lab-validated] - 2026-09-30

### Validated
- P01LAB-BUNDLE-R1 created and validated successfully
- bundle ID bnd-de6f9f2af21fc179ae1f
- 8 artifacts and 5 credentialed evidence files
- 9 SHA256 inventory entries verified
- outer bundle SHA256 verified
- no Secret Provider references or secret-like payload fields
- transport remains agnostic between offline/manual and future connected upload

## [0.5c.0-candidate] - 2026-09-30

### Added
- localhost-only Central Ingestion API
- POST /api/v1/bundles raw evidence-bundle upload
- GET /api/v1/bundles/{bundle_id} receipt/status summary
- health endpoint
- bounded streaming upload with mandatory Content-Length
- mandatory X-P01-Bundle-SHA256 validation
- optional Idempotency-Key bound to validated bundle_id
- delegation to the same v0.5b offline importer

### Security
- non-loopback bind rejected in v0.5c
- no caller-controlled storage path
- staging before validation/import
- oversized and hash-mismatched uploads rejected
- no network discovery, customer authentication, secret resolution or arbitrary payload execution
- TLS/node authentication intentionally deferred to v0.5d

### Tests
- loopback-only bind policy
- hash mismatch
- upload size guard
- common importer delegation
- idempotency-key mismatch
- safe status projection
- health endpoint
- unsupported content-type rejection

## [0.5e.1-candidate] - 2026-09-30

### Added
- managed Network Discovery stage in the Portable Discovery Node runtime
- `run` command with scanner profile/ports/timeout/workers/max-hosts controls
- explicit `--ack-authorized-scan` gate
- Assessment Manifest authorized-scope enforcement
- automatic application of manifest exclude scopes
- Network Discovery evidence stored inside the run workspace
- state/hash checkpoint for the managed discovery artifact
- resume guard: completed discovery returns `already_complete` with zero second scan
- explicit `--force-rescan` guarded against stale downstream completed steps

### Security
- no credential resolution or authentication in managed discovery
- no scan outside effective manifest-authorized IPv4 scope
- no dynamic scope expansion
- no server-initiated remote execution
- manifest authorization remains required before active discovery

### Next
- P01LAB runtime validation of managed Network Discovery on 192.168.100.0/24
- then internalize Credential Planner as the next managed stage

## [0.5e.0-candidate] - 2026-09-30

### Added
- portable-first Discovery Node runtime entry point
- `doctor`, `init`, `status`, `export` and `upload`
- isolated per-assessment/per-run workspace
- SHA256-protected runtime state and runtime config
- deterministic step/checkpoint model
- artifact hash tracking and bounded event history
- wrapper around the validated v0.5a Evidence Bundle
- wrapper around the validated v0.5d connected uploader
- portable runtime state JSON schema

### Safety
- runtime state/config reject plaintext password fields, Secret Provider locators and private-key material
- doctor performs no network activity
- active discovery/authentication orchestration is explicitly deferred to v0.5e.1
- completed bundle creation is never repeated silently
- completed connected upload is never repeated silently
- private-key path is used only for the upload invocation and is not stored in runtime state
- explicit `--force-rebuild` / `--force-resend` required to repeat completed transport/package work

### Tests
- workspace creation with spaces/cross-platform path handling
- init idempotency
- state/config SHA256 integrity
- state tamper detection
- secret-material guard
- export resume behavior
- connected-upload no-silent-repeat behavior
- doctor no-network invariant

### Next
- P01LAB runtime gate using existing validated evidence and v0.5d server
- v0.5e.1 orchestration of Network Discovery -> Planner -> Executor -> Asset Resolver

## [0.5d.0-candidate] - 2026-09-30

### Added
- explicit `mtls` transport mode for Central Ingestion API
- TLS 1.2+ server context with mandatory client-certificate verification
- authenticated node identity derived from client certificate DNS SAN / CN fallback
- `X-P01-Node-ID` binding to certificate identity
- bundle `node_id` binding to authenticated node
- authenticated-node scoping for bundle status lookup
- Discovery Node HTTPS/mTLS uploader
- upload receipt JSON + SHA256
- bounded transport-only retries

### Security
- localhost mode remains loopback-only
- non-loopback remote operation requires complete mTLS trust material
- server certificate and hostname are verified by the uploader
- TLS/auth/application validation failures are not retried automatically
- no private key, Secret Provider value or customer credential is persisted in upload receipts
- no server-initiated execution is introduced

### Validation
- unit coverage for transport configuration, certificate-node identity, node/bundle mismatch, status scoping, HTTPS-only uploader policy and retry semantics
- next gate: real P01LAB mTLS upload using the existing validated `.p01bundle`

## [0.5c.1-lab-validated] - 2026-09-30

### Validated
- localhost positive ingestion path and idempotent repeat upload
- bundle status lookup and edge/server semantic equivalence
- non-loopback bind rejection
- missing/malformed SHA256 -> HTTP 400
- wrong SHA256 -> HTTP 422
- tampered bundle -> HTTP 422
- oversized upload -> HTTP 413
- pre-body rejection connection hygiene: no follow-on parser noise after 400/413

### Result
Central Ingestion API v0.5c.1 is LAB VALIDATED and v0.5d connected authenticated transport is next.

## [0.5c.1-candidate] - 2026-09-30

### Fixed
- close HTTP/1.1 connection on upload rejection detected before request-body consumption
- prevent unread rejected body bytes from being parsed as a subsequent request
- eliminate follow-on `Bad request version` / `414 URI Too Long` noise observed after missing-SHA and oversized-upload negative gates

### Validation
- P01LAB negative gates already confirmed expected primary responses:
  - missing/malformed SHA256 -> HTTP 400
  - wrong SHA256 -> HTTP 422
  - tampered bundle -> HTTP 422
  - oversized request -> HTTP 413
- regression tests require `Connection: close` on missing-SHA and oversized pre-body rejections
- final runtime rerun only needs to confirm no follow-on parser error after those early rejections

## [0.5c.0-positive-path-pass] - 2026-09-30

### Validated
- API 0.5c.0 served on 127.0.0.1:8088
- health endpoint returned HTTP 200
- first bundle upload returned imported / HTTP 201
- repeated upload returned already_imported / HTTP 200
- GET bundle status returned HTTP 200
- semantic_match=true and edge/server semantic digests matched
- non-loopback bind 0.0.0.0 was rejected

### Remaining
- negative transport gates: missing SHA256, wrong SHA256, tampered bundle and oversized request

## [0.5b.0-lab-validated] - 2026-09-30

### Validated
- import receipt JSON/SHA256 independently verified
- receipt SHA256 9907e79835be9ae6b96d84155a6cd35f06d5f60340a8ecabe85d1c36e66b3de0
- outer bundle SHA256 verified
- 8 artifacts and 9 inventory entries preserved
- server-side Asset Resolver semantic digest matched edge result
- second import returned already_imported
- no network access, authentication, secret resolution or arbitrary payload execution

## [0.5b.0-functional-pass] - 2026-09-30

### Validated
- first offline import returned imported
- server-side Asset Resolver replay produced 5 logical assets, 0 unresolved, 0 ambiguous and 0 conflicts
- edge/server semantic digest matched
- second identical import returned already_imported
- receipt file-pair independent SHA256 verification remains pending upload

## [0.5a.0-candidate] - 2026-09-30

### Added
- portable .p01bundle creation
- bundle manifest with deterministic logical bundle ID
- SHA256 payload inventory
- optional source sidecar verification before packaging
- outer bundle SHA256 sidecar
- transport-agnostic connected/offline metadata
- bundle validation CLI

### Security
- Secret Provider references and secret-like JSON fields are rejected
- duplicate ZIP entries, path traversal and symlink entries are rejected
- file-count and uncompressed-size guards reduce archive abuse risk
- no network access, authentication or secret resolution is performed
- v0.5a explicitly does not claim publisher authenticity; digital signatures are a later stage

### Tests
- create + validate
- expected bundle layout
- tampered payload rejection
- secret reference rejection
- plaintext password-field rejection
- required source sidecar enforcement
- duplicate entry rejection
- traversal rejection
- stable logical bundle ID

## [0.4c.0-lab-validated] - 2026-09-30

### Validated
- 5 Network Discovery assets + 5 credentialed FULL observations -> 5 logical assets
- 0 unresolved observations
- 0 ambiguous correlations
- 0 conflicts after separating authentication realm from directory realm identity
- offline-only, no network access, authentication or secret resolution
- JSON/SHA256 evidence integrity verified

### Fixed
- management host local authentication context is preserved as `authentication_realm=local` and no longer overrides directory identity `P01LAB / p01.lab.test`

## [0.4c.0-candidate] - 2026-09-30

### Added
- offline Asset Resolver foundation
- Network Discovery + WinRM/SSH credentialed evidence correlation
- optional Assessment Manifest realm provenance
- field-level provenance and evidence strength
- explicit conflict records
- deterministic asset IDs from seed identity anchors
- JSON + SHA256 output
- evidence-directory/run-label selection for executor target bundles

### Safety
- IP alone never auto-merges assets
- MAC alone never auto-merges Network Discovery observations
- medium identity requires namespace + network corroboration
- exact strong identifiers may auto-correlate
- no network access, secret resolution, authentication, pivoting or scope expansion
- secret-provider references are rejected from resolver output

### Tests
- five-asset P01LAB synthetic correlation
- IP-only negative merge
- FQDN-only negative merge
- hostname+IP positive merge
- same-MAC Network Discovery preservation
- realm provenance semantics
- conflict preservation
- deterministic asset IDs
- secret-material guard
- SHA256 sidecar requirement

### Next
- run v0.4c.0 against the real P01LAB Network Discovery R2 + Multi-target FULL R1 evidence

## [0.4b.6-lab-validated] - 2026-09-30

### Validated
- interactive Assessment Manifest creation and validation
- structured rich credential profile intake without secret values
- compatible declared + observed namespace evidence produced one workstation adapter candidate
- declared-only realm with incompatible observed FQDN produced zero adapter candidates
- both planner gates retained secret_resolution=false and authentication_attempts=false
- manifest/profile/plan integrity evidence archived

## [0.4b.6-candidate] - 2026-09-30

### Added
- non-secret Assessment Manifest schema and CLI
- credential onboarding wizard that writes profile metadata only
- credential taxonomy for realm kind, realm name, target classes, privilege class, purposes and realm evidence
- planner v0.4b.3.2 support for Assessment Manifest
- declared/observed realm provenance and conflict recording
- high-privilege profile acknowledgement and conservative budget validation
- placeholder username linting

### Security
- declared domain context alone never becomes effective realm evidence
- rich taxonomy profiles do not match when runtime context is absent
- observed hostname/domain evidence is required by default for wizard-created AD profiles
- conflicting realm evidence blocks planning rather than being silently reconciled
- secrets remain outside manifest/profile files

### Validation
- unit tests cover manifest validation, declared-only gating, observed realm promotion, high-privilege policy and context conflicts
- P01LAB Planner validation remains the next runtime gate

## [0.4b.5-candidate] - 2026-09-30

### Added
- multi-target Credentialed Executor
- dry-run mode with zero secret resolution/authentication
- reviewed-plan SHA256 verification before execute mode
- profile snapshot drift guard
- hashed credential identity IDs without persisting raw secret refs
- shared-credential failure budget and circuit breaker
- SSH failure classification aligned with WinRM semantics
- per-target evidence JSON/SHA256
- aggregate job JSON/SHA256
- sequential execution only in the first candidate

### Security
- `not_planned` assets are never dispatched
- only authentication failures consume shared credential budget
- transport failures do not poison credential health
- execute mode requires explicit authorization acknowledgement
- no pivoting or dynamic-scope expansion

### Validation pending
- five-asset P01LAB dry-run before any multi-target authentication

## [0.4b.4.3-windows-matrix-validated] - 2026-09-30

### Validated
- Windows 11 domain workstation matched one dedicated /32 WinRM profile
- AUTH-only succeeded with one attempt and zero retries
- full WinRM enrichment completed with all collection sections passing
- secure channel was checked and healthy on the domain workstation
- only one subnet-level candidate network was emitted and auto-scan remained disabled
- no secret was persisted in AUTH or FULL evidence
- Windows credentialed matrix now covers local server, domain controller and domain workstation

### Next
- v0.4b.5 multi-target credentialed executor with shared-credential circuit breaker

## [0.4b.5-dry-run-lab-validated] - 2026-09-30

### Validated
- reviewed Credential Plan integrity bound to executor job by SHA256
- 5 planned actions, 5 ready, 0 blocked, 0 skipped
- dry-run resolved no secrets and made no authentication attempts
- deterministic order across DC01, MGMT01, W11, Ubuntu and Rocky
- shared domain identity recognized between DC01 and W11
- zero credential circuits open
- concurrency fixed at 1

### Next
- multi-target AUTH-only using the same reviewed plan and sidecar SHA256

## [0.4b.5-auth-lab-validated] - 2026-09-30

### Validated
- multi-target executor AUTH-only against five planned P01LAB assets
- deterministic serial execution with concurrency 1
- 5/5 actions completed and authenticated successfully
- zero preflight blocks, zero skips, zero authentication failures, zero open circuits
- shared domain credential identity accumulated two successes across DC01 and W11
- every target JSON matched its SHA256 sidecar and the digest recorded in the job
- the reviewed Credential Plan digest was propagated to every target result
- no secret values, secret refs, or credential locators were persisted to target outputs

### Security
- credential circuits remained closed because no authentication failure occurred
- successful authentications did not consume credential failure budget
- full enrichment remains a separate next-stage validation

## [0.4b.5-full-lab-validated] - 2026-09-30

### Validated
- multi-target full enrichment completed across 5 planned assets
- 5 actions ready, 5 completed, 5 authentication successes
- WinRM full collection completed for DC01, MGMT01 and W11
- SSH full collection completed for Ubuntu and Rocky
- zero skipped actions, zero authentication failures and zero open circuits
- target JSON/SHA256 evidence matched hashes recorded in the aggregate Job
- shared domain credential identity recorded two successes with circuit remaining closed

### Architecture
- v0.4b.6 is proposed as Assessment Context & Credential Intake before Asset Resolver
- operator-declared domain/realm and credential metadata remain policy/hints, never substitutes for discovered evidence
- Secret Provider remains separated from Credential Profiles

## [0.4b.3.1-positive-profile-gate] - 2026-09-30

### Validated
- Windows 11 workstation with WinRM and realm P01LAB matched exactly one dedicated workstation/domain profile
- /32 scope, service, realm, hostname, device type, OS family and confidence selectors all matched
- planner emitted `adapter_candidate`
- planner still resolved no secret and made no authentication attempt
- all five current LAB assets had exactly one adapter candidate

### Configuration hygiene
- latest plan exposed a placeholder username (`P01LAB\\SEU_USUARIO`) in the DC profile; this must be corrected before future multi-target execution

## [0.4b.4.1-candidate] - 2026-09-30

### Fixed
- split WinRM full collection into small independent PowerShell sections
- avoid the v0.4b.4 `The command line is too long.` failure caused by one oversized encoded run_ps payload
- preserve successful sections when another section fails

### Added
- per-section collection evidence
- `failed_section_count`
- `collected_with_section_failures` status
- unit regression test that keeps every PowerShell section below the configured size bound

### Validated
- WinRM/NTLM authentication succeeded against P01-MGMT01 with one bounded /32 profile attempt and zero retries
- v0.4b.4 full collection failure reproduced and isolated to payload size, not credentials or WinRM connectivity

## [0.4b.3.1-candidate] - 2026-09-30

### Added
- explicit per-asset `credentialed_action_status`
- explicit `skip_reasons` for no supported management protocol or no eligible credential profile
- summary counters for assets skipped by protocol/profile gating

### Rationale
A domain-joined Windows 11 host with WinRM stopped demonstrated that empty protocol plans are safe but not sufficiently explanatory for audit/reporting. The planner now records why no credentialed action is planned.

## [0.4b.3-validation] - 2026-09-30

### Validated
- domain-joined Windows 11 workstation was discovered with High confidence while WinRM was stopped
- scanner found Windows-associated ports but no 5985/5986
- planner regression test now guarantees that a Windows/domain context alone does not create a WinRM adapter candidate when no WinRM service was discovered

### Security
- reinforces the rule that asset discovery does not imply credential attempts
- protocol availability remains a mandatory gate before credential profile selection

## [0.4b.3.1-no-profile-gate-validation] - 2026-09-30

### Validated
- Windows 11 workstation exposed WinRM HTTP after controlled LAB preparation
- Planner detected WinRM but found zero eligible workstation profiles
- emitted `action=no_eligible_profile`
- emitted `credentialed_action_status=not_planned`
- emitted `skip_reasons=["no_eligible_profile_for_detected_protocols"]`
- no secret resolution and no authentication attempt occurred

### Security
Protocol availability does not authorize credential use. Credential selection still requires an explicit matching profile.

## [0.4b.3.1-protocol-gate-validation] - 2026-09-30

### Validated
- the Windows 11 workstation was rescanned after WinRM was manually enabled as LAB preparation
- Network Discovery detected TCP/5985 as `winrm-http`
- the scanner still performed zero credential attempts
- JSON/SHA256 integrity passed

### Next safety gate
- run the Planner before creating a workstation profile
- expected result: WinRM detected but no eligible workstation profile -> `not_planned` with `no_eligible_profile_for_detected_protocols`

## [0.4b.3.1-lab-validated] - 2026-09-30

### Validated
- Windows 11 negative WinRM credential gate using real Network Discovery evidence
- Windows workstation was classified with High confidence while WinRM was unavailable
- Planner emitted `credentialed_action_status=not_planned`
- Planner emitted `skip_reasons=["no_supported_management_protocol_detected"]`
- no secret was resolved and no authentication was attempted
- domain, local-Windows and Linux profiles remained isolated by protocol/context

## [0.4b.4.3-candidate] - 2026-09-30

### Fixed
- classify WinRM failures as transport, authentication, or remote-execution/unknown
- transport timeouts no longer count against a credential failure budget
- successful authentication explicitly clears failure classification

### Validated from DC01 R1 evidence
- an AUTH-only run hit a transient ConnectTimeout
- a later full run with the same profile authenticated successfully and collected all sections
- therefore the timeout is transport evidence, not proof of invalid credentials

### Security
- this classification is required before the future multi-target circuit breaker so connectivity faults do not poison shared credential health

## [0.4b.4.2-lab-validated] - 2026-09-30

### Validated
- P01-MGMT01 WinRM full enrichment completed successfully
- all modular collection sections passed
- candidate-network filtering returned only subnet-level networks
- JSON/SHA256 integrity passed
- zero warnings and zero errors

### Next
- validate a dedicated domain profile against P01-DC01

## [0.4b.4.2-candidate] - 2026-09-30

### Fixed
- Windows PowerShell 5.1 compatibility in identity, OS, hardware and hotfix sections
- empty-array JSON serialization uses `ConvertTo-Json -InputObject`
- route-derived /32 host/broadcast entries are no longer emitted as candidate networks

### Validated in R2
- WinRM/NTLM authentication and context-aware /32 local profile selection
- modular collection preserved successful sections after partial failures
- interfaces, routes, DNS, firewall, secure channel, local administrators, WinRM service and server roles were collected
- P01-MGMT01 exposed the intended connected networks while auto-scan remained disabled

### Remaining
- rerun P01-MGMT01 with v0.4b.4.2 to close the four PowerShell 5.1 section failures

## [0.4b.4-candidate] - 2026-09-30

### Added
- Windows WinRM credentialed enrichment adapter
- NTLM password transport for first LAB iteration
- context-aware profile selection before secret resolution
- fixed read-only PowerShell/CIM payload
- Windows identity/domain/OS/hardware/network/DNS/firewall/hotfix collection
- candidate-network generation with auto-scan disabled
- WinRM JSON Schema and unit tests

### Security
- no WinRM enablement or firewall modification
- no secret persistence
- bounded profile attempts and stop-after-success
- no secure-channel repair actions

## [0.4b.3-lab-validated] - 2026-09-30

### Validated
- context-aware planner processed 4 P01LAB assets
- Ubuntu and Rocky each matched only their dedicated /32 SSH profile
- Windows assets received no credential profile before WinRM profiles existed
- planner resolved no secrets and made no authentication attempts
- JSON/SHA256 integrity

### Remaining
- multi-target runtime circuit breaker for shared credentials

## [0.4b.2.1-lab-validated] - 2026-09-30

### Fixed
- classify SSH authentication that succeeds without usable exec-channel output as `authenticated_no_exec_output`
- add harmless SSH exec capability probe before read-only enrichment

### Validated
- Ubuntu 26.04 SSH authentication and full read-only enrichment via P01-MGMT01
- Rocky Linux 10.2 SSH authentication and full read-only enrichment via P01-MGMT01
- one matching credential profile, one attempt, zero same-profile retries per host
- hostname, OS/kernel, interfaces, routes, IPv4 forwarding and candidate networks
- candidate networks remain unassessed and are never auto-scanned in v0.4b
- JSON/SHA256 integrity and no secret persistence

## [0.4b.2-candidate] - 2026-09-30

### Added
- SSH credentialed enrichment adapter
- Credential Manager profile integration
- password authentication with bounded profile attempts
- TOFU and strict SSH host-key policies
- SHA256 host-key fingerprint evidence
- fixed read-only remote-command allowlist
- interface, route and IPv4-forwarding enrichment
- candidate-network generation with auto-scan disabled
- SSH enrichment JSON Schema and unit tests

### Security
- no secret value persisted to output
- no SSH agent or implicit local key use for password profiles
- no sudo/configuration commands
- no recursive scanning or pivoting
- one authentication attempt per matched profile

## [0.4.1-candidate] - 2026-09-29

### Fixed
- Warn when the selected scope contains no local IPv4/default gateway while still allowing routed scans
- Prefer local execution-host identity over reverse DNS for the scanner host
- Bind SSDP discovery to in-scope local IPv4 interfaces when possible

### Added
- `hostname_source` and `hostname_confidence`
- `mac_address_type` to distinguish locally administered MACs
- same-MAC/multiple-IP identity correlations without automatic deduplication
- summary counters for unique MACs and multi-IP MAC correlations
- unit tests for MAC classification and identity correlation

### Validated
- First real home/LAB scan discovered all IP endpoints visible in the supplied router evidence
- One logical device was observed under two IPs, confirming the need for the Asset Resolver

## [0.4.0-candidate] - 2026-09-29

### Added
- Network Discovery Scanner MVP
- Multiple IPv4 CIDRs/ranges and exclusions
- Scope guardrail and explicit authorized-scan acknowledgement
- ICMP, ARP-neighbor, TCP connect and SSDP discovery signals
- Reverse DNS, basic banners, HTTP/HTTPS fingerprinting
- Device/OS heuristic classification with confidence
- JSON + SHA256 network discovery output
- Unit tests for scope parsing and basic classification
- Source-of-truth policy for GitHub vs Google Drive

### Security
- No credential attempts in v0.4a
- No exploit probes
- Large scopes require explicit override

## [0.3.0-candidate] - 2026-09-29

### Added
- AD stale user/computer assessment data model
- Windows secure channel status
- Windows SMB share + NTFS correlation
- IIS FTP posture
- Linux Samba share assessment
- Linux FTP posture
- Linux password-policy collection
- Additional Analyzer rules for FTP, shares, stale identity, password policy and secure channel

### Validated
- FTP plaintext detection on vsftpd and IIS FTP
- Unknown TCP/21 classified as unconfirmed encryption posture
- Positive/negative SMB permission correlation
- Samba confirmed/potential/read-only scenarios
- Linux password baseline and failed systemd service

### Known validation limitation
- AD stale end-to-end lab simulation attempted to alter system-managed logon timestamps and did not produce the intended stale state. Use reduced threshold / never-logged-on objects and synthetic tests.

## [0.2.1] - 2026-09-29

### Fixed
- Windows PowerShell 5.1 compatibility for Generic List conversion
- Explicit conversion of collector errors, limitations and warnings with `.ToArray()`
- Network IP configuration list conversion
- Metadata counters now use converted arrays

## [0.2.0] - 2026-09-29

### Added
- Explicit errors, limitations and warnings collections
- Expanded runtime and privilege metadata
- Improved network discovery structure
- AD/GPO optional collection behavior
- Analyzer and deterministic rule engine foundation

## [0.1.0] - 2026-09-28

### Added
- Initial Windows/AD discovery collector
- JSON output
- SHA-256 integrity file
- Initial laboratory validation
