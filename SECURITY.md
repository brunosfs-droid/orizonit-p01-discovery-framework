# Security Policy

## Data classification

Discovery outputs can expose sensitive infrastructure information. Treat real customer output as **CONFIDENTIAL — CUSTOMER DATA**.

## Never commit

Do not commit passwords, API tokens, private keys, credential files, production inventories, raw customer outputs, discovery JSONs, logs with confidential data, or private certificates.

## Active network discovery

Network discovery is active probing and must only be executed against explicitly authorized scope.

v0.4a:
- requires `--ack-authorized-scan`;
- does not attempt credentials;
- does not run exploit scripts;
- has scope and concurrency guardrails.

## Credentialed discovery

v0.4b must use a Secret Provider abstraction. Configuration may contain only references such as `secret_ref`, never plaintext secrets.

Credential selection must be constrained by:
- protocol;
- target scope;
- priority;
- retry limit;
- lockout protection.

Authentication failures must not trigger uncontrolled credential spraying.

## Least privilege

Use dedicated technical identities. Separate discovery identities by technology when practical: Windows/AD, Linux/SSH, SNMP, virtualization and vendor APIs.

## Evidence integrity

Use SHA-256 for collected artifacts. Hashes detect accidental or post-collection changes but are not equivalent to digital signatures. Signed release/evidence manifests may be added later.

## Vulnerability reporting

Do not disclose repository or customer vulnerabilities in public issues. Use private communication approved by Orizon IT.


## SSH credentialed enrichment

- use only credential profiles matched to the target/protocol scope;
- use at most bounded profile candidates and never repeat the same password automatically;
- disable implicit SSH agent/local-key fallback for password profiles;
- execute only the hard-coded read-only command allowlist;
- do not use sudo or configuration commands;
- default lab policy may use TOFU; strict host-key validation is preferred when trusted host keys are available;
- host-key changes after TOFU enrollment must be treated as a security failure;
- networks learned from remote interfaces/routes are evidence only and must not trigger recursive scanning automatically.
