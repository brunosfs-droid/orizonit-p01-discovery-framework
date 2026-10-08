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

## Incremento backend23–25 (07/10/2026)

[Workspace Model](WORKSPACE_MODEL_v0.6.25.md) e
[ADR0039](ADR_0039_Workspace_Model_v0.6.25.md) fixam histórico append-only,
observado/declarado, grafo manual limitado, revisão transacional e preview/apply
idempotente. O adapter registra operações como jobs e revalida respostas.
Categoria observada identity; sem backfill completo, API humana, UI/Mapper ou
ações em dispositivos. Gates adicionais: drift/replay, sessão perdida/rollback,
close durante commit/preparação, autoria/RLS/FKs A/B e isolamento de sources.
R03–R05 continuam parciais; R06 depende de migração/restore/API e regressão.

## Ponte legada schema9 v0.6.28

workspace_legacy_plans referencia a prévia de identidade e seu snapshot verificado;
workspace_legacy_imports referencia collection e mapping administrativo, conservando
avaliações históricas e links ordinal → objeto. Ambos são imutáveis sob FORCE RLS.
Apply compõe identidade/cópia/recibos numa revisão. IDs de assets/findings antigos
não são substituídos; objetos workspace têm IDs próprios. [Contrato](WORKSPACE_LEGACY_v0.6.28.md).
