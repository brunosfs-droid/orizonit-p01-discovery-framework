# ADR 0021 — Apache 2.0 and Community/commercial editions

Date: 02/10/2026 (-03). Status: accepted product/license decision.

## Context

Bruno Feitoza explicitly replaced the earlier AGPLv3 product strategy with
Apache-2.0, a stable Community first and a future paid edition with specific
modules and no commercial item quota. He also approved the staged post-1.0
inventory/mapper/dependency recommendation.

## Decision

Apply the unmodified Apache License 2.0 terms to the current Cancã-owned source;
preserve attribution and update active licensing/contribution/product documents.
Use the official Apache-maintained license text from
https://raw.githubusercontent.com/apache/commons-lang/master/LICENSE.txt
(the FAQ permits HTTPS license URLs), checked against the license sections.

Maintain separate future commercial module code/license boundaries and retain
third-party licensing obligations. Official Community limits do not restrict
Apache rights and can be changed by recipients in their own derivatives.

Keep the planned Orizon IT CLA; finalize the Apache-aligned agreement and
acceptance process before opening public contributions. Do not assume an
unsigned draft supplies permissions for old third-party contributions.

## Provenance review and limits

Reviewed main at 6e040af501470d80d76ede889f29a00ade4167f1, tree
80d560fb8e4c3561d659b1480337cdb92246b1d5. The two commit-list pages
contained 106 commits, all with author Bruno Feitoza. No independent external
contribution was identified in that history. Existing NOTICE attributes the
product to Orizon IT; dependencies are declared separately, including
non-vendored LGPL Paramiko.

Commit attribution is a bounded repository observation, not independent proof
of ownership of every line or a complete dependency/binary license audit.
Any later-discovered third-party content requires its original obligations and
explicit compatible authorization before relicensing.

## Consequences

- Community recipients can use, modify and redistribute commercially; forks
  can remove open-source limits. Commercial value must have actual product,
  service and separately licensed module differentiation.
- Existing AGPL distributions/history are preserved; no retroactive revocation.
- Numeric quotas, module allocation, pricing and entitlement architecture remain
  open. No paid-edition licensing infrastructure delays Community 1.0.
- Safety, provenance and release-quality requirements apply to both editions.
- This commit changes license and documentation only: no runtime, schema,
  evidence, LAB deployment, quota or billing mutation.

## Validation

Compare LICENSE bytes with the fetched Apache-maintained text; review active
license references, file scope, preserved historical documents and unchanged
executable/schema paths. Existing repository CI remains the merge gate.

See [licensing and editions](LICENSING_AND_EDITIONS.md).
