# Cancã v0.6.71 — bloqueio de INSERT SQL direto pelo leitor

Teste PostgreSQL 16/17: após revogar e reconceder `workspace:read`, a role exclusivamente leitora não pode inserir diretamente linhas em `canca.workspace_scan_decisions`. O PostgreSQL deve retornar `InsufficientPrivilege`. O histórico aprovado permanece inalterado e nunca autoriza execução.

Gate: `tests/test_workspace_intent_ledger.py` no Workspace Foundation CI, com os oito workflows aprovados antes de merge. A v0.6.70 foi integrada pelo PR #181. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker seguem pendentes.
