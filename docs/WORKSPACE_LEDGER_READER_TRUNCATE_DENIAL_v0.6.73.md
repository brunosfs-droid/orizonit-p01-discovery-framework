# Cancã v0.6.73 — proteção contra TRUNCATE por leitor

Teste de integração PostgreSQL 16/17: após revogação e reconcessão de `workspace:read`, a role leitora não pode executar `TRUNCATE TABLE canca.workspace_scan_decisions`. A falha SQL esperada é isolada em uma transação aninhada (savepoint); uma decisão aprovada continua íntegra e não executável.

Gate: Workspace Foundation CI e os oito workflows obrigatórios. v0.6.72 integrada no PR #183. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster permanecem pendentes.
