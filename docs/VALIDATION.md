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
