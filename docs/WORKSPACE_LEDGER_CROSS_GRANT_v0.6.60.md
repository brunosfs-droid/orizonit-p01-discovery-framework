# Cancã v0.6.60 — concessão de leitura vinculada ao workspace

Teste SQL em PostgreSQL 16/17: `canca_ws_a` lê A, mas não herda autorização para B. Leitor autorizado em B não enxerga intenção originada em A (`intent_not_found`). Nenhuma execução de scanner.

Gate: `tests/test_workspace_intent_ledger.py`, Workspace Foundation CI e oito workflows. v0.6.59 integrada pelo PR #170. E0/EVE-NG e R02/R06 permanecem pendentes.
