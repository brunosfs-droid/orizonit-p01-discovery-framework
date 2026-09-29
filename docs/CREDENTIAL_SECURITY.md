# Credential Security Architecture — v0.4b

## Principles

1. Profiles contain metadata and secret references only.
2. Secret values never appear in Git, profile JSON, discovery JSON, findings or logs.
3. Credential selection is bounded by protocol and network scope.
4. Candidate attempts are ordered and capped to protect account lockout thresholds.
5. Authentication adapters must stop after a successful suitable profile.
6. Every attempt must be auditable by profile ID, protocol, target and result — never by secret value.
7. Dedicated least-privilege discovery identities are preferred over production administrator accounts.

## Initial Secret Providers

- `wincred://` — Windows Credential Manager; suitable for the current Windows-based LAB node.
- `env://` — temporary automation/CI integration; avoid persistent plaintext environment configuration.
- `prompt://` — interactive ephemeral secret entry.

## Planned Enterprise Providers

Adapters may later support enterprise secret managers such as HashiCorp Vault, Azure Key Vault or AWS Secrets Manager. The profile contract should continue to expose only a `secret_ref` abstraction.

## Authentication policy

A discovered open port does not authorize blind authentication. The future Credentialed Enricher must first map the observed service to a compatible protocol and then request only credential profiles eligible for that protocol and target scope.

Example:

```text
TCP/22 detected
  -> SSH adapter
  -> credential profiles protocol=ssh, scope contains target
  -> ordered by priority/specificity
  -> at most configured candidate count
  -> stop on success
```

Never try Windows credentials on SSH, SNMP communities on HTTP, or every stored credential against every IP.
