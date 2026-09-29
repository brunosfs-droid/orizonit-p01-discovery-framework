# Schemas

The schema directory contains contracts used between collectors and downstream
analysis.

## Current strategy

During the laboratory phase, schema `0.2` strictly defines the common envelope:

- `metadata`
- `data`
- `errors`
- `limitations`
- `warnings`

The `data` object remains extensible while Windows and Linux collectors are
being validated. Once platform fields stabilize, platform-specific definitions
can be added without losing the common envelope.

## Versioning

A collector declares its expected schema in:

```json
"schema_version": "0.2"
```

Breaking schema changes require a new schema version.
