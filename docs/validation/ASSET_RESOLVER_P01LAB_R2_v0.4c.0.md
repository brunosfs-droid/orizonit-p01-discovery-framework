# P01 Asset Resolver v0.4c.0 — P01LAB R2

**Status:** LAB VALIDATED

## Runtime result

- Network assets: 5
- Credentialed observations: 5
- Logical assets: 5
- Correlated observations: 5
- Unresolved observations: 0
- Ambiguous correlations: 0
- Assets with conflicts: 0
- Assets with strong identifiers: 2

## Safety

- offline_only = true
- read_only_mode = true
- secret_resolution = false
- authentication_attempts = false
- network_access_performed = false

## R1 defect resolved

R1 exposed a false realm conflict on the management Windows server because the credential authentication realm (`local`) was incorrectly treated as canonical directory identity.

R2 validates the corrected model:

- authentication_realm = local
- realm_name = P01LAB
- realm_dns_domain = p01.lab.test
- realm_evidence_state = credentialed_confirmed
- conflicts = 0

## Acceptance

The current v0.4c.0 acceptance contract is satisfied: five network observations plus five credentialed FULL observations resolved into exactly five logical assets, with no unresolved, ambiguous, or conflicting identities.

The Asset Resolver remains offline-only and consumes immutable evidence; it does not scan, authenticate, resolve secrets, pivot, or expand scope.
