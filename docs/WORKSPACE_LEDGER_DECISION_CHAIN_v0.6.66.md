# Cancã v0.6.66 — preservação da cadeia completa de decisões

Teste PostgreSQL 16/17: uma intenção registra `approved` seguida de `consumed` (duas decisões sequenciais). Após revogar e reconceder `workspace:read`, o histórico mantém exatamente as duas decisões, autores, timestamps e sequências `[1, 2]`, sem permitir qualquer execução ou atividade de rede.

Gate: `tests/test_workspace_intent_ledger.py` no Workspace Foundation CI e oito workflows obrigatórios. v0.6.65 integrada pelo PR #176. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker permanecem pendentes.
