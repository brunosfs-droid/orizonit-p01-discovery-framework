# ADR 0010 — Explicit bounded scheduling and review after interruption

Date: 2026-10-01 (-03). Status: accepted design; implementation v0.5f.3
LAB VALIDATED for bounded offline R1 on 2026-10-02 (-03).
Refs #83; follows ADR 0007/0008/0009. LAB acceptance is a separate evidence gate.

## Problem

Manual Windows/Linux hosts call the canonical agent once. Long-running hosts need
explicit scheduling while preserving independent stage grants, single-workspace
locking, interrupted-stage review and invocation-only transport. Restarting a host
must not replay an interrupted session, including one killed between stage invocations.

## Decision

Use one shared scheduler around canonical `run_once`; do not duplicate stage logic.
Service config v0.5f.3 explicitly opts in and bounds attempts to 1..10000. Default is
disabled; legacy three-key service configs keep manual behavior. Installation requires
disabled scheduling and all-denied grants. Enabling occurs explicitly after installation.
Policy schedule supplies a strict 60..86400-second fixed delay, independent of grants.

The first tick is immediate. Delay begins after completion; no parallel ticks, catch-up,
automatic recovery or retry. Each tick reloads protected config/policy, revalidates
identity/artifacts and acquires the canonical native workspace lock. Policy denial
consumes an attempt without dispatch. Failure/review halts; completion or budget ends
the session. Cooperative stop wakes waits but does not cancel live operations.

Persist a separate strict flat session journal plus SHA256 before any tick. A running
or halted session blocks later service invocations until documented operator review,
including a switch back to manual mode. Preserve canonical schema v0.5f, agent v0.5f.0
and runtime v0.5e.6. No transport or credential paths enter scheduler configuration,
journals or fixed host messages. Upload transport remains invocation-only.

OS services retain manual start, no restart/recovery actions, dedicated unprivileged
identity, pinned command/config and stopped-only removal. They idle after the worker
ends; running OS status does not establish active scheduling or successful assessment.

## Consequences and validation

Configuration path/budget changes halt rather than silently relocating or extending a
session. Policy grants/limits can be revoked between ticks. Journal retention is manual
and requires disk monitoring; automatic deletion/rotation is deferred. Review records
are archived only after reconciliation of checkpoints, artifacts and external effects.
This release supplies no unattended recovery or review-clearing command.

Tests use accelerated Event waits for 200 denied ticks and strict negative contracts.
Native CI/LAB uses actual 60-second delays on SCM/systemd, verifies policy reread,
budget idle and interruption during a subsequent wait, and requires zero replay on
restart. A two-tick native R1 is bounded short-duration evidence, not a multi-day soak,
live principal qualification, cancellation test or POST reconciliation qualification.
Windows P01-MGMT01 and Rocky P01-LNX-RKY01 R1 passed: exit 0, real two-tick
cycles, interrupted-wait intent and zero-invocation review on restart. Eight captures
and an independent Rocky journal/query support the bounded acceptance. Raw journals
were not supplied; extended/multi-day soak and live principal qualification remain
unqualified. [Acceptance](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md).
