# Data Model

## Common envelope

```json
{
  "metadata": {},
  "data": {},
  "errors": [],
  "limitations": [],
  "warnings": []
}
```

### metadata

Execution identity and provenance:

- collector name/version;
- schema version;
- UTC collection timestamp;
- host identity;
- execution identity;
- privilege profile;
- run label;
- runtime information;
- duration and counters;
- read-only declaration.

### data

Platform-specific inventory.

Windows currently groups data into:

```text
system
network
security
services
optional
active_directory
```

Linux will follow the same principle while using platform-appropriate sections.

### errors

A requested collection operation failed.

### limitations

Collection completed with known reduced visibility.

### warnings

A noteworthy condition that does not make the section fail.

## Why separate errors, limitations and warnings?

An assessment system must distinguish:

- **could not collect**;
- **collected, but with reduced confidence/visibility**;
- **collected successfully, but something deserves attention**.

That distinction becomes important when the Analyzer later produces findings
and confidence levels.
