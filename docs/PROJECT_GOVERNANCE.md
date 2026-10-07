# Cancã Project Governance

Cancã is the open-source product identity of Orizon IT Product 01 (P01).

## Project model

- **Software license:** Apache License 2.0 (Apache-2.0).
- **Maintainer:** Orizon IT.
- **Contribution model:** Apache-2.0 contributions with rights/provenance review; the planned Orizon IT CLA and acceptance flow must be finalized before public contributions open.
- **Trademark:** the software license does not grant unrestricted use of the Cancã or Orizon IT brands, logos, or visual identity.
- **Engineering source of truth:** GitHub.
- **Product governance and validation evidence:** Orizon IT controlled repositories and OneDrive/SharePoint (Google Drive is legacy).

## Product principles

1. Open by default.
2. Evidence before opinion.
3. Read-only before automation.
4. Secure by design.
5. API-first.
6. Distributed by design.
7. Vendor-neutral.
8. Explainable findings.
9. Community-driven.
10. Enterprise-ready.

## Scope discipline

Every new proposal is classified as:

- **A — MVP:** necessary for the workspace/Mapper/intelligence/action-planning 1.0 specification.
- **B — Post-MVP:** valuable, but not required for 1.0.
- **C — Experiment:** research or prototype.
- **D — Out of product scope.**

The control question is:

> Is this required by PRODUCT_SPEC_1.0.md and its acceptance gates, or is it a later extension?

## Release maturity

### Technical Alpha
Internal engineering and controlled LAB validation. Breaking changes are allowed.

### Design Partner Alpha
Controlled external environments with structured feedback.

### Community Beta
Public repository, reproducible installation, contribution/security policies, support matrix, SBOM, third-party license inventory, and documented limitations.

### Release Candidate
Feature freeze, hardening, upgrade/rollback, backup/restore, compatibility and blocker closure.

### 1.0 GA
A supportable end-to-end product with reproducible installation, stable core contracts, usable reports, security controls and operational documentation.

## Commercial ecosystem

The open-source project is intended to support a commercial ecosystem around:

- infrastructure assessments;
- support plans;
- professional services;
- integrations and custom collectors;
- managed services;
- training and future certification;
- hosted/SaaS operation.

The approved distribution strategy is Community first, with its first stable
release preceding a commercial edition with specific modules and no commercial
item quota. The official Community distribution will have documented feature and
item limits. Exact values, counting semantics, prices and module allocation
remain undecided; no runtime quota is introduced by this decision.

Apache-2.0 rights apply to the open core, including commercial use and modified
redistributions. Official distribution limits are not additional Apache license
restrictions and may be changed in forks. Future proprietary modules must retain
separate code and licensing boundaries. Safety budgets, permissions and technical
capacity limits apply to every edition.

Community must provide a useful assessment workflow, security controls and
evidence integrity. Paid modules must not remove access to already-open code,
rewrite immutable evidence or weaken core security. See
[licensing and editions](LICENSING_AND_EDITIONS.md) and
[ADR 0021](ADR_0021_Apache_2_0_and_Editions.md).

The 06/10/2026 (-03) rebaseline brings server inventory, Mapper, network/virtualization
intelligence and service dependencies into 1.0. Workspaces are isolated, sites
exist inside them, one workspace is open per installation, and server administration
is separate from the workspace overview. See [specification](PRODUCT_SPEC_1.0.md),
[ADR 0036](ADR_0036_Workspace_First_1.0.md) and [backlog](BACKLOG_1.0.md).
Edition allocation/quotas remain open. Product Alpha is not closed until the
extended architectural foundation is implemented and qualified.

## Release planning and truth

The specification is the current product scope; ADRs describe decisions, backlog
links requirements to tests, and roadmap orders deliveries. Historical evidence
remains pinned. A planning document is not an implementation or LAB acceptance.
No cross-workspace correlation is permitted. No continuous NMS is required.
Scope reductions require an explicit product decision and updated traceability.

## Architecture governance

Architecture-changing work should be documented through an ADR/RFC before implementation when it affects:

- trust boundaries;
- data contracts;
- schemas;
- authentication;
- credential handling;
- persistence;
- plugin boundaries;
- backward compatibility;
- licensing or redistribution.

## Security boundary

Cancã is an infrastructure assessment platform, not an exploitation framework.

- scanning requires explicit authorization;
- collectors are read-only first;
- credentials are scope/protocol/context constrained;
- secrets must never be persisted in evidence bundles;
- discovered assets are not silently used as pivots;
- remote connected transport uses authenticated channels;
- customer evidence never belongs in Git.

## Naming transition

**Cancã** is the official product name.

P01 remains temporarily valid inside filenames, schemas, headers and validated artifacts during Technical Alpha. Internal renaming will be performed as a controlled compatibility change rather than a global search/replace.

