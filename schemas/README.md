# Schemas

JSON Schemas define the interchange contract used by P01 components.

Current candidate: `p01-discovery-schema-v0.3.json`.

Older schema files may remain in this directory when compatibility testing requires coexistence. Unlike ordinary source files, schema versions are protocol contracts and may legitimately be stored side by side.

Validation example:

```bash
python -m json.tool schemas/p01-discovery-schema-v0.3.json > /dev/null
```
