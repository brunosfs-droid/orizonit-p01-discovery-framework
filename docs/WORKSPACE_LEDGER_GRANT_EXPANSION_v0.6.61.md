# Cancã v0.6.61 — grants adicionais não vazam histórico entre workspaces

Teste PostgreSQL 16/17: conceder à role `canca_ws_a` acesso de leitura também ao workspace B não revela uma intenção aprovada anteriormente no workspace A. Ao reabrir A, o histórico é visível apenas no escopo correto e a geração anterior permanece não executável (`context_current=false`, `execution_authorized=false`).

Qualificação via `tests/test_workspace_intent_ledger.py` e Workspace Foundation CI; merge somente após os oito workflows aprovados. A v0.6.60 foi integrada pelo PR #171. E0/EVE-NG, R02/R06, restauração cross-cluster e maker/checker continuam pendentes.
