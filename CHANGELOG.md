# Changelog

All notable changes to the P01 Discovery Framework are documented here.

## [Unreleased]

### Planned
- Validate AD stale behavior with reduced-threshold lab and synthetic tests
- Credential Manager and credentialed enrichment (v0.4b)
- Asset Resolver / deduplication (v0.4c)
- Reporting Engine v0.1

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
