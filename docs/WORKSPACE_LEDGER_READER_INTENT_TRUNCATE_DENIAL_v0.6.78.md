# Cancã v0.6.78 — negação de TRUNCATE sem CASCADE em intenções por leitor

Teste integrado PostgreSQL 16/17: role exclusivamente leitora revogada e novamente autorizada com `workspace:read` não pode executar `TRUNCATE TABLE canca.workspace_scan_intents` sem CASCADE. O erro de privilégio é isolado por savepoint, preservando intenção, decisão e a não autorização de execução.

Gate: Workspace Foundation CI, PostgreSQL CI e oito workflows obrigatórios antes de merge. A v0.6.77 foi integrada pelo PR #188. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster continuam pendentes.
