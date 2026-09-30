# Schemas

JSON Schemas define the interchange contract used by P01 components.

Current candidate: `p01-discovery-schema-v0.3.json`.

Older schema files may remain in this directory when compatibility testing requires coexistence. Unlike ordinary source files, schema versions are protocol contracts and may legitimately be stored side by side.

Validation example:

```bash
python -m json.tool schemas/p01-discovery-schema-v0.3.json > /dev/null
```


## v0.4b.6 contracts

- `p01-assessment-manifest-schema-v0.4b.6.json` — non-secret pre-flight environment context.
- `p01-credential-profiles-schema-v0.4b.json` — backward-compatible profile contract extended with credential taxonomy fields.


## v0.4c contracts

- `p01-asset-resolver-schema-v0.4c.json` — canonical logical asset, provenance, conflict and correlation output contract.
