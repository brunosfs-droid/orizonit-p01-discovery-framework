# Windows 11 Workstation WinRM R4 — v0.4b.4.3

Date: 2026-09-30

## Result

The dedicated workstation/domain profile matched exactly one target and one WinRM protocol plan.

AUTH-only:
- one matching /32 profile
- selector score 90
- one attempt
- zero same-profile retries
- NTLM authentication success
- failure category null
- does not count against credential failure budget
- no secret persisted

Full enrichment:
- authentication success
- collection status collected
- failed sections 0
- identity, OS, hardware, interfaces, routes, DNS, firewall, secure channel, local administrators, hotfixes, WinRM service and roles all collected
- workstation is domain joined
- secure channel checked and healthy
- one subnet-level candidate network
- auto-scan disabled
- no warnings or errors

## Windows matrix

Validated scenarios now include:
- Windows Server with local realm/profile
- Domain Controller with domain realm/profile
- Domain workstation with domain realm/profile

## Engineering note

The adapter metadata version is 0.4b.4.3, but one informational limitation string still mentions 0.4b.4.2. This is non-functional and is corrected with this documentation update.

## Next

Implement v0.4b.5 multi-target credentialed executor with shared-credential circuit breaker before moving to Asset Resolver v0.4c.
