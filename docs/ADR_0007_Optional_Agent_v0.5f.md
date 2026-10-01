# ADR 0007 — Optional agent foundation

Status: Accepted for v0.5f.0 implementation; LAB validation pending.
Date: 2026-10-01. Scope: Issue #83.

## Decision

The portable v0.5e.6 runtime remains the only discovery engine. The optional
agent calls its Python functions and advances at most one checkpoint per
`run-once`. Policy grants are independent for discovery, planning, dry-run,
AUTH-only, FULL, resolver, export and upload. Missing grants deny execution.
Policy is bound to assessment/run/node identity, rejects unknown properties,
and contains no credentials, provider locators or transport key paths.

The policy SHA256 is recorded per invocation. SHA256 detects change, it is not
a signature: policy and workspace write access remain an OS permission boundary.
Credentials remain in the existing Secret Provider workflow. Interactive prompt
providers are rejected for unattended AUTH/FULL; upload transport inputs are
invocation-only. No provisioning or server-driven execution is added.

A shared workspace OS lock covers portable mutations and agent decisions,
execution and journaling. It is nonblocking and reentrant within the same thread.
The lock file is retained to prevent inode replacement races; process exit releases
the kernel lock. A filename's existence alone never signifies a running agent.

Before dispatch, the agent validates state/config sidecars, workspace identity,
checkpoint shape, and all recorded artifacts and hashes. Failed/interrupted
checkpoints require operator review; no unattended retry or force flags exist.
Persisted dispatch intent blocks replay after interruption, including upload
before its runtime checkpoint. Per-invocation journal JSON/SHA256 records only fixed status codes, stage,
timestamps and policy digest, never raw exceptions, stage results or transport.

The optional interval schedule is descriptive only in this release. Installation,
service identities, recovery and actual scheduling belong to v0.5f.1–v0.5f.3.
Portable/manual usage remains supported.

## Consequences and validation

The agent cannot bypass manifest scopes, runtime input bindings, failure budgets,
strict SSH host keys or the existing mTLS uploader. A completed workspace resumes
without transport parameters and without invoking any completed stage.
CI must exercise policy denial, progression, integrity failures, concurrent
processes, portable/agent lock interoperability, sanitized failure journals,
and Windows/Linux lock behavior. Real P01LAB acceptance remains a separate gate.
