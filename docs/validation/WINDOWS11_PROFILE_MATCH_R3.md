# Windows 11 Positive Profile Match R3

Date: 2026-09-30

## Result

The Context-aware Credential Planner v0.4b.3.1 processed the P01LAB discovery dataset after WinRM had been detected on P01-W11-01.

For the Windows 11 workstation:
- target: 192.168.100.30
- realm: P01LAB
- protocol: winrm
- profile: p01lab-w11-01-winrm-domain
- scope: /32
- selector score: 90
- matched selectors: device type, OS family, realm, service, hostname, minimum confidence
- action: adapter_candidate
- credentialed_action_status: adapter_candidate
- no skip reasons

Planner-level security remained intact:
- secret_resolution=false
- authentication_attempts=false

This closes the third workstation planning gate:
1. no protocol -> not planned
2. protocol but no eligible profile -> not planned
3. protocol + eligible authorized profile -> adapter candidate, still without secret resolution or authentication

Raw LAB JSON/SHA256 remains in Drive.

## Configuration hygiene observation

The same planner output exposed a placeholder username `P01LAB\SEU_USUARIO` in the DC profile. It did not affect workstation planning, but must be corrected before future multi-target execution.
