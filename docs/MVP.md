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
- essential SNMP/network-device read-only enrichment before Community Beta;
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

Product Alpha v0.6.x now starts with the PostgreSQL metadata foundation v0.6.0
(CANDIDATE): explicit indexing of validated imports, versioned migration and
atomic/idempotent transactions. The filesystem store and ingestion API remain
independent. PostgreSQL LAB qualification and backup/restore are pending.

The scheduler v0.5f.3 short offline R1 passed on Windows/Rocky. Extended soak
remains a separate pending gate and does not block synthetic persistence work.
See [status](STATUS_PERSISTENCE_v0.6.0.md) and [next steps](NEXT_STEPS_v0.6.0.md).

## Community Beta exit criteria

Before Community Beta the project must have:

- AGPLv3;
- operational CLA process;
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

