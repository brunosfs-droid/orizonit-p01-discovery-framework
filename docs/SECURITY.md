# Security Architecture

## Threat model summary

The framework handles infrastructure metadata that can materially help an
attacker understand a target environment. Therefore the discovery pipeline must
be treated as a privileged assessment system.

Primary risks:

- credential exposure;
- excessive privileges;
- lateral movement through the management host;
- leakage of collected output;
- malicious modification of collectors;
- tampering with evidence;
- accidental customer data publication.

## Controls

### Management host
- hardened dedicated management system;
- minimal inbound exposure;
- administrative access restricted to authorized operators;
- audit logging enabled;
- secrets stored outside the repository.

### Linux access
- dedicated account such as `orizoncollector`;
- SSH keys preferred over passwords;
- scoped sudo rules in production;
- direct root SSH disabled in production unless explicitly approved.

### Windows access
- dedicated technical account;
- least privilege;
- WinRM constrained to required source networks where used;
- no credentials embedded in scripts.

### Outputs
- classify as confidential;
- encrypt at rest where available;
- restrict access;
- define retention;
- generate integrity hashes;
- never publish production outputs to this repository.

## Laboratory exception

Lab configurations may temporarily use broader privileges to validate the
product. Those shortcuts are not production recommendations and must be removed
from deployment documentation before customer use.
