# Changelog

All notable changes to the P01 Discovery Framework are documented here.

## [Unreleased]

### Planned
- Validate AD stale behavior with reduced-threshold lab and synthetic tests
- Credential Manager and credentialed enrichment (v0.4b)
- Asset Resolver / deduplication (v0.4c)
- Reporting Engine v0.1

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
