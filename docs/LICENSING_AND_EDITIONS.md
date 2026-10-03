# Cancã licensing and editions

Approved by Bruno Feitoza on 02/10/2026, America/Sao_Paulo.

## Decision

- The Cancã-owned Community source is licensed under **Apache-2.0**.
- The first stable release is **Cancã Community**.
- The official Community distribution may have feature and item limits, with
  exact values/counting semantics still to be defined.
- A commercial edition follows development and qualification of specific
  modules, with no commercial item quota.
- Commercial modules are intended to have separate proprietary code/license
  boundaries. Their names, prices, packaging and final contractual terms are open.
- Support, assessments, integrations, managed services, training and hosting
  remain possible complementary revenue streams.
- No quotas, license server, entitlement enforcement or billing are implemented
  by this documentation/license change.

## Apache rights and official limits

Apache-2.0 permits use, modification and redistribution, including commercial
reuse and derivatives, subject to its terms. An official distribution's feature
or item limit is a product behavior, not an additional restriction on Apache
rights. Someone modifying the open source can remove such a limit or offer
their own distribution.

Keep LICENSE and applicable notices, identify modifications when redistributing
and observe the patent and trademark terms. Trademark protection does not
revoke the right to fork or use the software. Cancã is not an Apache Software
Foundation project or an ASF-endorsed product.

Future commercial code must not be published under Apache-2.0 if exclusivity is
intended. Publishing it under Apache grants rights that a later commercial
contract cannot withdraw from those recipients. Commercial distributions must
retain the open core's license/attribution and third-party obligations.

## Product quality and future quotas

Community remains useful for the authorized discovery-to-report workflow,
including security, evidence integrity and access to collected data.
Commercial differences concern modules, supported capabilities, official
capacity policy and service/support offerings.

Before adding quota code, specify:
- the counted object (assets, environments, concurrent runs or other units);
- deduplication and counts across reimports/history;
- where the limit is enforced and explained before work starts;
- behavior when an import exceeds the quota, without discarding evidence;
- upgrades/downgrades and continued access to existing reports;
- offline behavior and no mandatory telemetry/activation for Community.

No numeric quota or assignment of mapper/VMware/dependency modules to an edition
has been approved. "No item quota" in the paid edition does not mean unlimited
hardware capacity, unsafe scans or absence of permissions/time/credential budgets.

## Contributions and previous versions

Review contribution provenance and submission authority. Contributions to the
open core use Apache-2.0 (Section 5), subject to applicable separate agreements.
The existing planned Orizon IT CLA is retained; its final text and operational
acceptance flow remain to be completed before public contribution opens.

Historical commits/tags and copies previously distributed under AGPLv3 remain
historical AGPLv3 distributions; this change does not rewrite them or revoke
their recipients' rights. An independent third-party AGPL contribution cannot
be relicensed merely by replacing this repository's LICENSE.

Third-party dependencies retain their original licenses. Complete the actual
release SBOM/license inventory before packaging or redistribution.

## Approved development sequence

Community 1.0 assessment/security/reporting first. After 1.0:
1. Server inventory and import wizard.
2. Manual infrastructure mapper.
3. Qualified network interfaces/neighbors and topology enrichment.
4. Aggregates, VLANs and redundancy modeling.
5. VMware physical/virtual correlation.
6. Service dependency editing and potential impact reports.

These increments share entities/provenance in the server; collectors acquire
authorized evidence. Detailed designs, estimates, release dates and edition
allocation require the respective increments' specification.

## References

- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [Apache licensing FAQ](https://www.apache.org/foundation/license-faq.html)
- [ADR 0021](ADR_0021_Apache_2_0_and_Editions.md)
- [Dependency inventory](DEPENDENCIES.md)
- [Governance](PROJECT_GOVERNANCE.md)
