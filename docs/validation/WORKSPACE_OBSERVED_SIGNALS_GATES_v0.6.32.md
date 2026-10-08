# Cancã v0.6.32 — Qualification and operational gates

Checked baseline: main fd5efff0df93c89df74085474450cd6a4d9a5897 (v0.6.31), PR #142 merged.
Candidate: PR #143, feature/workspace-observed-signals-v0.6.32.

## Delivered in candidate
- Read-only observed signal projection from already-authorized object_state; bounded source observation history (100), 50 per page, max 1000 signal entries.
- Strict revision-fenced continuation; source paths excluded, provenance reduced to collection_id/ordinal/received timestamp.
- WorkspaceService workspace:read and HTTP GET /api/v1/workspaces/{workspace_id}/objects/{object_id}/signals.
- Fixed audit operation observed_signals; unit, HTTP and audit regression cases; PG16/17 workspace CI coverage.

## Release gates (do not conflate them)
1. **CI**: every required PR workflow must conclude success at the final head SHA, including Workspace Foundation PG16/17, Python, PostgreSQL, CodeQL and remaining configured workflows. Pending checks are not passing checks.
2. **Contract**: authorized same-workspace reads, denial of other workspace, after>0 requires expected_revision; duplicate/unrecognized query rejected; source paths and declarations not leaked by signal projection.
3. **Integration**: merge PR #143 only when gates 1–2 pass; verify main head and post-merge checks, changelog and plan as appropriate.
4. **Operational EVE-NG**: maintain separate open gate: import realistic evidence and inspect provenance, revision mismatch, unauthorized access and restore; collect operator evidence before declaring operational acceptance.
5. **Product Alpha**: remains open regardless of CI. Immutable evidence verification, complete migrations/adapters and end-to-end recovery are out of scope for this thin slice.

No recorded CI or EVE-NG pass is claimed by this planning document.
