# Changelog

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
