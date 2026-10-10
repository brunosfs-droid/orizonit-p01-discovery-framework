# SSH Credentialed Enrichment v0.4b.2.1 — LAB Validation

Date: 2026-09-30

## Result

The SSH credentialed enrichment path is LAB VALIDATED for controlled Linux targets through the P01-MGMT01 Discovery Node.

### Ubuntu
- authentication success;
- one matching credential profile;
- one attempt;
- zero same-profile retries;
- full collection status: collected;
- hostname, kernel/OS, interfaces, routes, IPv4 forwarding and candidate network returned.

### Rocky
- authentication success;
- one matching credential profile;
- one attempt;
- zero same-profile retries;
- full collection status: collected;
- hostname, kernel/OS, interfaces, routes, IPv4 forwarding and candidate network returned.

### Security
- secrets were resolved from the local Secret Provider;
- no secret values were persisted to output;
- candidate networks were emitted with auto-scan disabled;
- JSON/SHA256 integrity checks passed.

### Restricted appliance behavior
The prior home-router test remains valuable: authentication succeeded but the target did not provide usable exec-channel output. v0.4b.2.1 now classifies that condition explicitly instead of treating it as complete enrichment.

### Windows 11
The Windows 11 LAB endpoint was powered off during the Discovery Node baseline. Its absence was expected and will be tested during WinRM/WMI validation.

Raw LAB outputs remain in protected private legacy storage storage and are intentionally not committed to Git.
