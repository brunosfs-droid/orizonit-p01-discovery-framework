# Cancã v0.6.69 — replay terminal conflitante após regrant

Teste PostgreSQL real 16/17: após a sequência `approved` → `consumed`, com revogação e reconcessão de `workspace:read`, um reuso do request ID terminal com decisão conflitante é rejeitado. O histórico de duas decisões permanece intacto e `execution_authorized=false`.

Gate: `tests/test_workspace_intent_ledger.py`, Workspace Foundation CI e os oito workflows obrigatórios. v0.6.68 integrada pelo PR #179. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker ainda pendentes.
