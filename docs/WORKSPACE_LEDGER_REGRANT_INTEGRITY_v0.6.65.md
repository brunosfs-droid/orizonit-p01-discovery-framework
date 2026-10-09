# Cancã v0.6.65 — integridade das decisões após reconcessão de leitura

Teste PostgreSQL 16/17: registrar decisão `approved`, revogar `workspace:read` de uma role, validar bloqueio e reconceder leitura. A sequência de decisões antes e depois deve ser idêntica; a recuperação de leitura não autoriza execução de scanner ou atividade de rede.

Gate: `tests/test_workspace_intent_ledger.py` em Workspace Foundation CI e oito workflows aprovados antes do merge. v0.6.64 integrada via PR #175. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker permanecem pendentes.
