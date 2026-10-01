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

### Distributed mTLS R2

The next engineering gate is to separate the two roles physically:

- keep the Discovery Node on P01-MGMT01;
- run the Cancã Server on a second host;
- prove outbound-only node-to-server mTLS;
- validate hostname/certificate trust;
- bind node identity to client certificate and bundle;
- preserve SHA256, receipt and idempotency;
- distinguish transport failures from TLS/auth/application failures.

This gate must pass before central persistence and Product Alpha become the main focus.

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
