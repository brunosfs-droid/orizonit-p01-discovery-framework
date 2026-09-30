# Credential Manager — v0.4b.3

The Credential Manager is the secure profile/secret-resolution foundation for credentialed discovery.

## What is stored where?

`credentials.local.json` stores only metadata, scope, protocol, priority, username, contextual selectors and `secret_refs`.

The secret itself is stored in a Secret Provider. On Windows, `wincred://` uses Windows Credential Manager Generic Credentials.

## CLI commands

### validate

```powershell
python .\credential_manager\P01_Credential_Manager.py validate `
  --profiles .\credential_manager\credentials.local.json
```

Validates the JSON/profile contract and security rules.  
**It does not create an output file.** Result is printed to stdout.

### check

```powershell
python .\credential_manager\P01_Credential_Manager.py check `
  --profiles .\credential_manager\credentials.local.json `
  --profile-id home-router-ssh
```

Checks whether the referenced secret is available in the configured Secret Provider.  
It never prints the secret.  
**It does not authenticate to the target device.**  
**It does not create an output file.**

### match

```powershell
python .\credential_manager\P01_Credential_Manager.py match `
  --profiles .\credential_manager\credentials.local.json `
  --target 192.168.15.1 `
  --protocol ssh
```

Shows which profiles are eligible for a target/protocol. In v0.4b.3 the resolver can also evaluate discovery context such as device type, OS family, service, hostname/vendor, realm and confidence. Ordering uses priority, selector specificity and scope specificity.  
**It does not authenticate to the target device.**  
**It does not create an output file.**

Context-aware example:

```powershell
python .\credential_manager\P01_Credential_Manager.py match `
  --profiles .\credential_manager\credentials.local.json `
  --target 192.168.100.40 `
  --protocol ssh `
  --device-type "Linux/Unix Host" `
  --os-family "Linux/Unix-like" `
  --service ssh `
  --confidence Medium
```

A profile can define optional selectors:

```json
"selectors": {
  "device_types": ["Linux/Unix Host"],
  "os_families": ["Linux/Unix-like"],
  "services": ["ssh"],
  "hostname_patterns": ["p01-lnx-*"],
  "realms": ["P01LAB"],
  "min_confidence": "Medium",
  "allow_unknown": false
}
```

When context is supplied, an asset classified as Unknown receives no credential unless a profile explicitly sets `allow_unknown: true`.

### store-wincred

```powershell
python .\credential_manager\P01_Credential_Manager.py store-wincred `
  --target ORIZONIT/P01/home-router-ssh `
  --username admin
```

Stores a secret as a Generic Credential in Windows Credential Manager. Secret input is hidden.

You can inspect the presence of the entry through:

```powershell
cmdkey /list | Select-String "ORIZONIT/P01"
```

or via **Control Panel → Credential Manager → Windows Credentials → Generic Credentials**.

The secret value is not exposed by the P01 CLI.

## Security model

- no plaintext secrets in Git;
- no plaintext secrets in Google Drive;
- no plaintext secrets in JSON output;
- credential profiles are scoped by protocol/network;
- optional contextual selectors narrow eligibility by discovered service and asset identity;
- Unknown devices do not receive credentials by default when context-aware matching is used;
- `failure_budget_per_job` declares the maximum shared-profile failure budget for future orchestration;
- candidate attempts are bounded;
- protocol adapters must stop after a successful profile and prevent uncontrolled credential spraying.

## Validation status

v0.4b.1 foundation has been validated on Windows for:

- profile validation;
- Windows Credential Manager secret availability;
- target/protocol matching.

Real device authentication begins in v0.4b.2+.


## v0.4b.3 context-aware resolver

The resolver is designed to consume context derived from Network Discovery. It does not authenticate by itself.

Recommended hard gates:
- protocol;
- authorized IPv4 scope.

Optional contextual gates:
- device type;
- OS family;
- detected service;
- hostname/vendor pattern;
- authentication realm;
- minimum discovery confidence.

The future orchestrator will combine these decisions with a per-job failure budget/circuit breaker before invoking protocol adapters.
