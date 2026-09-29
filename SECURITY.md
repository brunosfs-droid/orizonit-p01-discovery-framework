# Security Policy

## Data classification

Discovery output can expose sensitive infrastructure information such as:

- hostnames;
- IP addresses and routes;
- domain and forest names;
- software and patch levels;
- administrative groups;
- services and roles;
- security configuration;
- Active Directory topology.

Treat real customer discovery output as **CONFIDENTIAL — CUSTOMER DATA**.

## Never commit

Do not commit:

- passwords;
- API tokens;
- private keys;
- certificates containing private keys;
- SSH private keys;
- production inventories containing credentials;
- raw customer outputs;
- secrets embedded in scripts.

## Credentials

Use dedicated technical identities and least privilege. Laboratory permissions
may be intentionally broad for validation, but production deployment must
restrict privileges to the minimum commands and data required.

## Reporting vulnerabilities

Do not disclose vulnerabilities from this repository or customer assessments in
public issues. Use a private communication channel approved by Orizon IT.

## Collector security principles

Collectors should be:

- read-only by default;
- transparent about collected fields;
- explicit about errors and limitations;
- local-first unless remote transfer is part of the documented workflow;
- free of hidden persistence or configuration changes.

## Integrity

Collectors should generate or support cryptographic hashes for collected
artifacts when practical. Current Windows output uses SHA-256.
