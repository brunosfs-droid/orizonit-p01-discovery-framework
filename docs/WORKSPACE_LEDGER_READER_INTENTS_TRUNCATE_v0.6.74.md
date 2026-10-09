# Cancã v0.6.74 — bloqueio de TRUNCATE CASCADE em intenções por leitor

Teste integrado PostgreSQL 16/17: após revogação e reconcessão de `workspace:read`, a role de leitura não pode executar `TRUNCATE TABLE canca.workspace_scan_intents CASCADE`, evitando apagar intenções e decisões dependentes. A negação SQL é isolada em savepoint e o histórico `approved` segue intacto, com `execution_authorized=false`.

Gate: Workspace Foundation CI e os oito workflows obrigatórios. v0.6.73 integrada pelo PR #184. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster continuam pendentes.
