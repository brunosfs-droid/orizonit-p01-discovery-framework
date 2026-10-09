# Cancã v0.6.72 — negação de UPDATE e DELETE SQL ao leitor

Teste integrado PostgreSQL 16/17: após revogação e reconcessão de `workspace:read`, uma role exclusivamente leitora não pode executar `UPDATE` nem `DELETE` direto na tabela `canca.workspace_scan_decisions`. Cada erro SQL esperado é isolado por savepoint para não invalidar a transação externa. O histórico de decisões permanece inalterado e `execution_authorized=false`.

Gate: Workspace Foundation CI, PostgreSQL CI e os oito workflows obrigatórios. A v0.6.71 foi integrada pelo PR #182. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster seguem pendentes.
