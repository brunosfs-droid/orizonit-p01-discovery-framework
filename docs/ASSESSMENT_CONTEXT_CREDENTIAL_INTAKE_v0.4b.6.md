# v0.4b.6 — Assessment Context & Credential Intake

## Decision

Add an explicit pre-flight layer before Asset Resolver.

The operator may know domains, realms, platform types and credential roles before scanning. This context is useful, but it must be treated as declared policy/hints rather than observed truth.

## Assessment Manifest

Non-secret fields may include:
- assessment/client/environment identifiers
- authorized scopes and exclusions
- DNS domains
- NetBIOS realm names
- forests/trusts when declared
- sites/locations
- discovery nodes
- allowed protocols/adapters
- safety policy

## Credential taxonomy

Profiles should separate:
- realm_kind: ad_domain, local_host, vcenter_sso, network_aaa, device_local, linux_local, other
- target_class: windows_server, windows_workstation, domain_controller, linux, vcenter, esxi, switch, router, firewall, storage, appliance
- protocol: winrm, ssh, snmpv3, https_api, ldap, later others
- privilege_class: read_only, inventory, operator, local_admin, domain_admin, platform_admin, network_admin
- purpose: discovery, inventory, configuration_audit, patch_assessment
- authorized scopes/selectors

Secrets remain in Secret Provider only.

## Runtime rule

Declared domain/realm data never authorizes authentication by itself.

Credential execution still requires:
- protocol discovered
- scope authorized
- context/profile selectors matched
- credential circuit healthy
- explicit execution authorization

## UX

Interactive setup is allowed as a wizard, but the wizard writes persistent configuration first. Scanner, Planner and Executor remain non-interactive for reproducibility and automation.

Suggested commands:

```
p01 assessment init
p01 credential add
p01 assessment validate
p01 discovery run
```

## Security

High-privilege profiles such as domain_admin/platform_admin/network_admin should:
- warn by default
- use failure budget 1
- execute sequentially by default
- require explicit acknowledgement
- never be selected as automatic fallback after a lower-privilege failure

## Placement

Implement after v0.4b.5 and before v0.4c Asset Resolver so the resolver and future VMware/network adapters can consume the richer context without later schema migration.
