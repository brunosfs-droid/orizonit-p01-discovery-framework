# Windows 11 no-WinRM gate validation

Date: 2026-09-30

## Scenario

A domain-joined Windows 11 workstation was powered on in the P01LAB network.

Ground truth:
- domain joined;
- Windows host;
- WinRM service stopped.

Network Discovery identified the workstation as a Windows Host with High confidence from Windows-associated services, but did not observe WinRM 5985/5986.

## Expected behavior

The Credentialed Discovery Planner must not generate a WinRM adapter candidate solely because the asset is Windows or belongs to the domain.

The required gate is:

1. asset context matches;
2. supported protocol is actually discovered;
3. a credential profile matches protocol + scope + selectors.

With WinRM absent, the workstation must have:
- no detected credentialed protocol;
- no WinRM protocol plan;
- zero adapter candidates;
- no secret resolution;
- no authentication attempt.

## Engineering action

A regression test was added to protect this behavior.

## Next LAB stage

After preserving this negative baseline, WinRM may be enabled manually as an explicit LAB preparation step, followed by:
- Network Discovery R2;
- workstation/domain profile creation;
- planner validation;
- WinRM auth-only;
- full enrichment.

The P01 product itself must not auto-enable WinRM on targets.
