# Credential Manager v0.4b.1 — Windows LAB R1

Sanitized validation result:

- profile document: valid;
- errors: 0;
- warnings: 0;
- three profiles loaded in the LAB file;
- Windows Credential Manager provider found the referenced SSH secret;
- matched `home-router-ssh` for target `192.168.15.1/32`;
- priority: 10;
- max attempts per target: 1;
- secret value was never printed.

Important distinction:

- `validate` validates configuration;
- `check` validates Secret Provider availability;
- `match` validates profile selection;
- none of these commands validates the username/password against the target.

**Status:** LAB VALIDATED — Credential Manager Foundation.
