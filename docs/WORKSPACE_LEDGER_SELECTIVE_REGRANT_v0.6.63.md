# Cancã v0.6.63 — reconcessão seletiva preserva isolamento

Teste integrado PostgreSQL 16/17: revogar e reconceder `workspace:read` em B à role também autorizada em A não expõe a intenção aprovada em A enquanto B estiver ativo. Ao retornar a A, o histórico permanece visível somente como evidência, com `context_current=false` e `execution_authorized=false`.

Gate: `tests/test_workspace_intent_ledger.py`, Workspace Foundation CI e oito workflows antes do merge. v0.6.62 integrada pelo PR #173. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker ainda pendentes.
