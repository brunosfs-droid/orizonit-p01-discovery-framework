# ADR 0030 — Offline revisions of local operator accounts v0.6.18

Date: 03/10/2026 (-03). Status: accepted for implementation; operational CANDIDATE.
Scope: A — MVP administration of server-local human accounts and exact read grants.

## Decision

Add a separate administrator CLI for inspecting a validated private policy and
generating a new private policy revision. Support add, set-grants, enable, disable
and rotate-password. Preserve the strict v1 schema, scrypt parameters, local
authentication/session model and existing Web/API contracts. Do not change the
portable collector, target credentials or Discovery Node identity.

Each mutation requires the inspected policy SHA256, an existing username except
for add, and a distinct output filename that must not exist. Grants are explicit,
case-sensitive assessment IDs; set-grants replaces the whole target set, with a
separate clear-grants option. Operator IDs/usernames of existing accounts remain
unchanged. No wildcard, implicit admin, remote write endpoint or account deletion.

Read and validate a bounded regular private source file through a descriptor,
reject aliases/reparse points and hardlinks, and detect normal read-time drift.
Only validated fields enter the revision. Read source/output directories under
administrator control; POSIX output directories must be private. Check the
source fence before password work and again immediately before publication.
This is a fence for the revision's base, not activation or a durable source lock.

Write at most 64 KiB in a new private staging file, flush/fsync, and publish via
an exclusive same-directory hardlink, which cannot replace an existing output.
Remove staging on ordinary exit; on process interruption a private staging file
may remain. The source is never rewritten. The output remains a candidate until
a controlled listener restart with that file. Filesystems lacking hardlink
publication fail closed. Windows ACLs must be configured by the administrator;
POSIX mode and CI temporary-directory tests are not an ACL deployment qualification.

Add and rotate-password require an interactive terminal and two matching hidden
prompts. Reuse the qualified password validator and salted scrypt record builder.
No passwords in command arguments, stdin pipes, environment configuration, JSON
output or logs. Parser/runtime errors return fixed codes without echoing supplied
arguments or raw exceptions. Inspection exposes only operator IDs/usernames,
enabled state, assessment IDs and whole-file SHA256; never salts/password hashes.

Revisions do not reload a live policy, revoke live sessions or activate a new
account. Existing listeners retain their immutable startup policy and absolute
session TTL until controlled restart. Success explicitly reports restart_required
and live_sessions_updated=false. Stop admission and drain requests before applying
an administrator-selected policy file, as in the existing deployment contract.

## Verification and deferred gates

Synthetic tests cover real scrypt/authentication, per-account isolation, empty
grants, disabled accounts, old listener snapshots/tokens, malformed/oversize
policies, wrong/stale fences, private directories, aliases/hardlinks/FIFOs,
exclusive output publication, injected failures and process interruption cleanup.
Use Linux/Windows CI for supported filesystem/crypto behavior. Existing Python,
PostgreSQL, Web/browser and agent suites must remain compatible. No new dependency.

No real account file, service, database, store, LAB host, firewall or target is
changed by this increment. Manual LAB tests remain deferred at the maintainer's
request. Production ACLs/backup/restart procedures and AD/SSO are separate gates.
