# WinRM P01-DC01 R1 — domain profile validation

Date: 2026-09-30

## Result

The dedicated domain profile matched P01-DC01 with protocol, /32 scope, realm, service, hostname and confidence selectors.

One AUTH-only execution encountered a transient ConnectTimeout before authentication could be established. A subsequent full run using the same profile authenticated successfully and completed all modular collection sections.

## Full run

- context realm: domain
- one matching profile
- one attempt
- zero same-profile retries
- authentication: success
- collection: collected
- failed sections: 0
- AD DS and DNS roles detected
- DC domain role observed
- secure-channel check intentionally not run for the DC
- one subnet-level candidate network
- auto-scan disabled
- no secret persisted

## Architecture conclusion

A transport timeout must not be treated as evidence that the credential is invalid. v0.4b.4.3 introduces failure classification so future shared-credential circuit breakers count only authentication failures against credential health.
