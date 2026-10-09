# Cancã v0.6.67 — fechamento terminal após reconcessão

Teste integrado PostgreSQL 16/17: após registrar `approved` → `consumed` e reconceder acesso `workspace:read`, a consulta histórica permanece não executável, e uma nova tentativa de consumo com outro request ID falha em `intent_transition_denied`, sem alterar decisões.

Gate: `tests/test_workspace_intent_ledger.py` em Workspace Foundation CI e oito workflows antes do merge. A v0.6.66 foi integrada pelo PR #177. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker seguem pendentes.
