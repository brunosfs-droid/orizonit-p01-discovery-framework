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

## Read-only / non-destructive expectations

Collectors must not modify system configuration. Network Discovery is allowed to generate authorized ICMP/TCP/SSDP probe traffic but must not:

- exploit vulnerabilities;
- perform brute force;
- spray credentials;
- change services;
- install software on targets;
- create persistence.
