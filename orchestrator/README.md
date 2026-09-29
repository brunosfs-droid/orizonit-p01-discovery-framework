# Orchestrator

The orchestrator is the planned central execution layer of the P01 Discovery
Framework.

## Responsibilities

- load target inventory;
- classify target platform;
- validate connectivity;
- select the correct collector;
- execute remotely;
- retrieve output;
- verify hashes;
- record execution status;
- prepare artifacts for analyzer/reporting.

## Non-responsibilities

The orchestrator should not contain platform-specific discovery logic that
belongs in collectors.

## Planned inventory format

See `inventory/hosts.example.csv`.

Credentials must never be stored in the CSV.
