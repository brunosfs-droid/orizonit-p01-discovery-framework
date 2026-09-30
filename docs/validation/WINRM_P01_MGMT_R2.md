# WinRM P01-MGMT01 R2 — v0.4b.4.1

Date: 2026-09-30

## Result

- WinRM/NTLM authentication: PASS
- one matching /32 profile
- one attempt
- zero same-profile retries
- secret not persisted
- modular collection: PARTIAL PASS
- successful sections: interfaces, routes, DNS, firewall, secure channel, local administrators, WinRM service, server roles
- failed sections: identity, operating_system, hardware, hotfixes
- JSON/SHA256 integrity: PASS

## Root causes

The four failed sections used statement keywords as parenthesized expressions (for example `(if(...))` or `(try{...})`), which is incompatible with Windows PowerShell 5.1 in this context.

The R2 result also exposed route-derived /32 entries being treated as candidate networks. Those entries describe local host/broadcast routes, not useful discovery expansion networks.

## v0.4b.4.2 fix

- replace parenthesized statement expressions with PowerShell 5.1-safe precomputed variables;
- use `ConvertTo-Json -InputObject` for arrays, including empty arrays;
- exclude route-derived /32 prefixes from candidate networks;
- add regression tests for PowerShell 5.1 syntax patterns and /32 filtering.

Expected candidate networks on P01-MGMT01 after the fix are the connected subnet-level networks only, including the LAB LAN and the NAT-connected network, with `auto_scan=false`.

Raw customer/LAB artifacts remain in protected Drive storage.
