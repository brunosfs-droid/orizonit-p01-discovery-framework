# Credential Manager — v0.4b.1

The Credential Manager is the secure profile/secret-resolution foundation for credentialed discovery.

## What is stored where?

`credentials.local.json` stores only metadata, scope, protocol, priority, username and `secret_refs`.

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

Shows which profiles are eligible for a target/protocol, ordered by priority and scope specificity.  
**It does not authenticate to the target device.**  
**It does not create an output file.**

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
- candidate attempts are bounded;
- later protocol adapters must stop after a successful profile and prevent uncontrolled credential spraying.

## Validation status

v0.4b.1 foundation has been validated on Windows for:

- profile validation;
- Windows Credential Manager secret availability;
- target/protocol matching.

Real device authentication begins in v0.4b.2+.
