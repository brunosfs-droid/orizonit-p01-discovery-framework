# WinRM P01-MGMT01 R3 — v0.4b.4.2

Date: 2026-09-30

## Result

- WinRM/NTLM authentication: PASS
- context-aware /32 local profile selection: PASS
- one attempt, zero same-profile retries
- all 12 modular collection sections: PASS
- JSON/SHA256 integrity: PASS
- warnings: 0
- errors: 0
- candidate networks: 2 subnet-level entries
- no secret value persisted to output

## Data groups collected

- identity and domain membership
- operating system and build
- hardware
- interfaces, routes and DNS
- firewall profiles
- member-computer secure channel
- local administrators
- recent hotfixes
- WinRM service
- Windows roles/features

## Candidate network behavior

The R2 /32 route noise was eliminated. The adapter retained only subnet-level candidate networks and preserved `authorization_status=unassessed` and `auto_scan=false`.

## Decision

WinRM Credentialed Enrichment v0.4b.4.2 is LAB VALIDATED for the P01-MGMT01 local-realm scenario.

Next validation: P01-DC01 using a separate domain credential profile.

Raw LAB artifacts remain in protected Drive storage.
