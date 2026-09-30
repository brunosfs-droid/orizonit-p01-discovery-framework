# Assessment Context & Credential Intake — v0.4b.6

This component captures **operator-declared, non-secret context** before discovery and writes structured credential-profile metadata.

It does not scan, resolve secrets, or authenticate.

## Why this exists

Operators often know useful facts before discovery: authorized scopes, AD domains/realms/forests, identity type, target class, protocol, privilege class and purpose. Context improves planning but declaration is never treated as proof.

## Evidence states

- `declared` — provided by the operator;
- `observed` — supported by discovery evidence, such as an observed FQDN suffix matching a declared AD domain;
- `credentialed_confirmed` — reserved for credentialed evidence / Asset Resolver promotion.

A domain profile can set `realm_evidence_min = observed`, so a declared domain alone cannot make it eligible.

## Create an Assessment Manifest

Interactive:

    python .\assessment\P01_Assessment_Context.py init --output C:\P01\assessment-manifest.json

Validate:

    python .\assessment\P01_Assessment_Context.py validate --manifest C:\P01\assessment-manifest.json

## Credential Intake

    python .\assessment\P01_Assessment_Context.py credential-add --manifest C:\P01\assessment-manifest.json --profiles .\credential_manager\credentials.local.json

The wizard writes only metadata and a Secret Provider reference. It never asks for or writes the actual secret.

Credential dimensions include `realm_kind`, `realm_name`, `target_classes`, `protocol`, `privilege_class`, `purposes`, `scopes` and `realm_evidence_min`.

## High-privilege profiles

`domain_admin`, `platform_admin` and `network_admin` require explicit acknowledgement and are constrained to one attempt per target and failure budget 1. Routine discovery should prefer `read_only` or `inventory` identities.

## Planner integration

    python .\orchestrator\P01_Credentialed_Discovery_Planner.py --discovery C:\P01\output\network.json --profiles .\credential_manager\credentials.local.json --manifest C:\P01\assessment-manifest.json --output-dir C:\P01\output

A domain listed in the manifest only becomes an effective realm when supported by observed evidence. The planner still requires detected protocol, authorized scope, compatible profile and the normal credential gates.

## Security rules

- no secrets in Assessment Manifest;
- no secrets in Credential Profile files;
- declared context is a hint, not authoritative fact;
- conflicting declared/observed realm information blocks planning rather than being silently reconciled;
- rich v0.4b.6 profiles do not match when runtime context is absent;
- runtime execution remains non-interactive and reproducible.
