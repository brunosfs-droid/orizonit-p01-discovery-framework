# Architecture

## 1. Purpose

The P01 Discovery Framework separates infrastructure assessment into four
logical concerns:

1. **orchestration** — where and how collectors run;
2. **collection** — platform-specific inventory;
3. **normalization and validation** — consistent machine-readable data;
4. **analysis and reporting** — findings, correlations and deliverables.

This separation allows collectors to stay small, auditable and reusable.

---

## 2. High-level architecture

```mermaid
flowchart TB
    USER["👤 Consultant / Operator"]

    subgraph ORCH["Management & Orchestration"]
        MGMT["🖥️ P01-MGMT01"]
        INV["📋 Inventory"]
        LOG["🧾 Execution Log"]
    end

    subgraph TARGET["Customer / Lab Infrastructure"]
        WAD["🪟 Windows Server / AD"]
        WCL["💻 Windows Client"]
        UBU["🐧 Ubuntu"]
        RKY["🐧 Rocky Linux"]
    end

    subgraph COLLECT["Collection Artifacts"]
        JSON["📄 JSON"]
        HASH["🔐 SHA-256"]
        META["⚠️ Errors / Limitations / Warnings"]
    end

    subgraph ANALYSIS["Analysis Layer"]
        VALID["✅ Schema & integrity validation"]
        NORM["🧩 Normalization"]
        CORR["🔎 Correlations"]
        FIND["🚨 Findings"]
    end

    subgraph DELIVERY["Delivery Layer"]
        TECH["📘 Technical Report"]
        EXEC["📊 Executive Summary"]
        DASH["📈 Dashboard"]
    end

    USER --> MGMT
    INV --> MGMT
    MGMT -->|"PowerShell / WinRM"| WAD
    MGMT -->|"PowerShell / WinRM"| WCL
    MGMT -->|"SSH"| UBU
    MGMT -->|"SSH"| RKY

    WAD --> JSON
    WCL --> JSON
    UBU --> JSON
    RKY --> JSON

    JSON --> HASH
    JSON --> META
    JSON --> VALID
    HASH --> VALID
    VALID --> NORM --> CORR --> FIND
    FIND --> TECH
    FIND --> EXEC
    FIND --> DASH
    MGMT --> LOG
```

---

## 3. Trust boundaries

```mermaid
flowchart LR
    subgraph A["Operator zone"]
        OP["Operator workstation"]
    end

    subgraph B["Management zone"]
        MG["P01-MGMT01"]
    end

    subgraph C["Target zone"]
        W["Windows"]
        L["Linux"]
    end

    subgraph D["Evidence zone"]
        O["Output repository / protected storage"]
    end

    OP -->|"administration"| MG
    MG -->|"authenticated remote execution"| W
    MG -->|"authenticated remote execution"| L
    W -->|"discovery result"| MG
    L -->|"discovery result"| MG
    MG -->|"validated artifacts"| O
```

Each boundary must be considered separately for authentication, authorization,
network exposure, logging and data retention.

---

## 4. Collection contract

A collector should return:

```text
metadata
data
errors
limitations
warnings
```

The exact platform data can differ, but common metadata and error semantics
should remain predictable.

### Errors

A collection section could not complete as intended.

### Limitations

The collector completed, but visibility was reduced by privilege, platform,
module availability or another known constraint.

### Warnings

The collector completed but detected a condition worth surfacing.

---

## 5. Remote execution model

The target state is central orchestration:

```mermaid
sequenceDiagram
    actor Operator
    participant MGMT as P01-MGMT01
    participant Host as Target Host
    participant Store as Evidence Storage

    Operator->>MGMT: Start assessment
    MGMT->>MGMT: Load inventory / select collector
    MGMT->>Host: Validate connectivity and identity
    MGMT->>Host: Execute read-only collector
    Host-->>MGMT: JSON result + SHA-256
    MGMT->>MGMT: Validate integrity/schema
    MGMT->>Store: Save approved artifact
    MGMT-->>Operator: Execution summary
```

---

## 6. Design decisions

- **JSON** is the primary interchange format.
- **SHA-256** provides artifact integrity evidence.
- Collectors must not require database access.
- Collectors should remain independently executable.
- Analyzer/reporting logic must not be embedded in collectors unless the logic
  is truly platform collection logic.
- Client-specific data must not be hard-coded into collectors.

---

## 7. Future architecture

Planned evolution includes:

- concurrent remote execution with throttling;
- encrypted credential handling;
- schema validation in CI and at runtime;
- persistent assessment datastore;
- rule engine for findings;
- evidence-to-finding traceability;
- dashboard and report generation;
- signed release artifacts.
