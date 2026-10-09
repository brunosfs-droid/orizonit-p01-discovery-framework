# Cancã v0.6.62 — revogação seletiva de leitura

Teste real PostgreSQL 16/17: uma concessão de leitura adicional em B é removida sem afetar a leitura legítima da mesma role no workspace A. Ao entrar em B, a role revogada não pode consultar o histórico. A consulta em A permanece somente histórica (`execution_authorized=false`).

Gate: `tests/test_workspace_intent_ledger.py`, Workspace Foundation CI e os oito workflows aprovados antes do merge. A v0.6.61 foi integrada no PR #172. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker continuam pendentes.
