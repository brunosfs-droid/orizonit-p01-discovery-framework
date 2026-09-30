# Orizon IT P01 — Asset Resolver v0.4c

## Purpose

Transform multiple observations into one logical asset without discarding provenance or creating unsafe identity assumptions.

## Evidence model

The resolver treats observations and assets separately.

An observation is immutable evidence from a source. A logical asset is a deterministic correlation result.

### Evidence strengths

- `declared`
- `weak`
- `medium`
- `observed`
- `strong`
- `credentialed_confirmed`

These strengths are used per field, not as a global source priority.

## Correlation policy

Automatic correlation is intentionally conservative.

### Auto-merge allowed

1. exact strong identifier; or
2. namespace match (`fqdn`/hostname) plus network match (`IP`/MAC).

### Auto-merge denied

- IP only;
- MAC only;
- FQDN/hostname only;
- declared realm only.

If no corroborated match exists, the observation becomes a separate logical asset and is recorded in `unresolved_observations`.

If multiple clusters have the same highest supported match score, no merge occurs; the observation becomes a separate asset and the candidates are recorded in `ambiguous_correlations`.

## Canonical fields

Current fields include canonical hostname, FQDN, realm name, realm DNS domain, realm evidence state, device class, OS family and operating system.

Every field keeps `field_provenance`.

## Conflict policy

No silent overwrite.

If multiple medium-or-strong claims disagree, the resolver preserves all claims, records a conflict and uses strength followed by deterministic tiebreak only for the canonical view.

Analyzer/Reporting can later surface these conflicts to the operator.

## Initial P01LAB acceptance

Existing evidence should resolve into five assets:

- P01-DC01
- P01-MGMT01
- P01-W11-01
- P01-LNX-UBU01
- P01-LNX-RKY01

The expected correlation is one Network Discovery observation plus one credentialed FULL observation for each host.

## Security

The resolver is offline-only.

Metadata must always state:

- `offline_only=true`
- `read_only_mode=true`
- `secret_resolution=false`
- `authentication_attempts=false`
- `network_access_performed=false`

Outputs must never contain secret-provider references or secret-like fields.
