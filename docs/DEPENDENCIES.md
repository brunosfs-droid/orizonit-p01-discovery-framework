# Third-Party Dependencies

## Paramiko

P01 SSH Credentialed Enrichment v0.4b.2 uses **Paramiko** as an optional runtime dependency for SSH client functionality.

- upstream: https://github.com/paramiko/paramiko
- current dependency range: `paramiko>=5.0,<6`
- upstream license: **LGPL-2.1**
- distribution model in P01: **not vendored**; installed separately from PyPI/environment

Before any commercial redistribution or packaging strategy changes, Orizon IT should perform a formal third-party license review and preserve the required license notices/obligations.

The P01 source repository does not contain a copy of Paramiko source code.

## Apache-2.0 migration and packaging boundary

Changing the Cancã-owned source license does not change dependency licenses.
Do not replace third-party notices with Apache-2.0 or label an entire bundle
Apache-only when other components are included.

Current optional dependency declarations to review for each actual release:

| Contract | Declared dependency |
| --- | --- |
| SSH enrichment | `paramiko>=5.0,<6` |
| WinRM enrichment | `pywinrm>=0.5,<1` |
| SNMP enrichment v0.4b.7 | `pysnmp==7.1.24`, `pyasn1==0.6.3`, `cryptography==46.0.3`, `cffi==2.0.0`, `pycparser==2.23` |
| PostgreSQL | `psycopg[binary]>=3.2,<4` |
| Windows service | `pywin32==312; sys_platform == "win32"` |

This is a direct-dependency checklist, not a complete SBOM or a completed
binary-redistribution review. Exact resolved versions, transitive dependencies,
binary contents (including bundled libraries), notices and applicable obligations
must be inventoried for Community and commercial installers independently.

## Optional SNMP runtime

The standalone adapter uses [PySNMP 7.1.24](https://pypi.org/project/pysnmp/7.1.24/),
an upstream BSD-2-Clause implementation. The qualified versions are declared in
[requirements-snmp.txt](../credentialed_enrichment/requirements-snmp.txt), including
the ASN.1 and cryptographic runtime. They are installed separately, not vendored.
The CI additionally uses jsonschema 4.25.1 to validate synthetic output contracts;
it is not needed to run the adapter. This adds an explicit optional runtime,
not a complete SBOM or approval to redistribute its wheels/bundled libraries.
