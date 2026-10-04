# Cancã MVP 1.0

## Goal

Prove that Cancã can transform an authorized infrastructure environment into a traceable, reproducible and secure technical/executive assessment.

Required value flow:

    AUTHORIZE
      -> DISCOVER
      -> ENRICH
      -> RESOLVE
      -> INGEST
      -> ASSESS
      -> FIND
      -> REPORT

The MVP ends at **recommendation**. General-purpose automation and remediation are post-MVP.

## In scope

- authorized IPv4 network discovery;
- distributed Discovery Node;
- secure credential profiles and Secret Provider abstraction;
- SSH and WinRM enrichment;
- essential SNMP/network-device read-only enrichment before Community Beta; single-target [SNMP v0.4b.7 adapter](../credentialed_enrichment/README-SNMP.md) is CANDIDATE with independent loopback CI, automatic pipeline integration remains pending;
- Assessment Manifest;
- logical Asset Resolver;
- Evidence Bundle;
- offline import;
- outbound connected upload using HTTPS/mTLS;
- central persistence;
- deterministic rule engine;
- findings with evidence/provenance;
- technical report;
- executive report;
- minimal web interface;
- API;
- operational logging, receipts and troubleshooting;
- install/upgrade/backup documentation before GA.

## Out of scope for 1.0

- full NMS/metric monitoring;
- patch deployment;
- automatic remediation;
- vulnerability exploitation;
- full enterprise CMDB;
- full IPAM;
- full automatic dependency mapping;
- general AI decision authority;
- public multi-tenant SaaS;
- billing;
- marketplace;
- arbitrary server-initiated command execution on Discovery Nodes.

## Non-negotiable gates

- no secret material in evidence/logs/bundles;
- no credential spraying;
- no silent asset merge on IP alone;
- no customer data in Git;
- deterministic and traceable findings;
- bundle integrity verification;
- connected/offline semantic equivalence;
- mTLS identity binding in remote connected mode;
- reproducible installation before Community Beta;
- dependency/license review and SBOM for public releases.

## Current gate

Distributed mTLS R2 passed on separate hosts, including certificate/hostname
trust, node binding, semantic equivalence and cross-host idempotency.

Product Alpha v0.6.x includes PostgreSQL indexing, lifecycle, asset identity,
historical findings and fenced technical/executive reporting. Synthetic Rocky R1
for basic PostgreSQL, recovery, lifecycle and CLI technical export passed, as did
local operator API and the initial Web R1. New Web downloads/selection/executive
preview, offline account revisions, opt-in private operator audit and read-only
audit review remain operational CANDIDATE, with manual
tests deferred by the maintainer on 03/10/2026. The filesystem store and ingestion
API retain their independent boundaries; full production roles/TLS/recovery are
separate gates.

The scheduler v0.5f.3 short offline R1 and ten-tick/60-second extended soak passed
on Windows/Rocky. Multi-day and live AUTH/FULL/POST qualification remain separate;
accepted R1/soak gates should not be repeated for subsequent synthetic development.
See [status](STATUS_PERSISTENCE_v0.6.0.md) and [next steps](NEXT_STEPS_v0.6.0.md).

## Community Beta exit criteria

Before Community Beta the project must have:

- Apache License 2.0 (Apache-2.0), LICENSE/NOTICE and release-specific dependency obligations;
- finalized Orizon IT CLA and operational contribution/provenance process;
- CONTRIBUTING;
- SECURITY;
- Code of Conduct;
- issue/PR templates;
- release process;
- support matrix;
- SBOM;
- third-party license inventory;
- installation guide;
- architecture documentation;
- documented known limitations;
- basic backup/restore procedure.


## Release edition

The first stable launch is **Cancã Community**, under Apache-2.0. A paid edition
follows qualification of specific modules; paid licensing/billing infrastructure
is not a prerequisite for Community 1.0. Official Community feature/item limits
must be specified and disclosed before release; no values or runtime quotas are
introduced here. Stable means the same release-quality and security gates above.

Server inventory/manual mapping and later network/VMware/service dependency work
are approved post-1.0 increments. Their Community/commercial allocation is open.
See [licensing and editions](LICENSING_AND_EDITIONS.md).
