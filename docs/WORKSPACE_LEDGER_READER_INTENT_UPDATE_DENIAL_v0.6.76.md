# Cancã v0.6.76 — negação de UPDATE direto em intenções por leitor

Teste PostgreSQL 16/17: após revogação e reconcessão de `workspace:read`, uma role exclusivamente leitora não pode executar `UPDATE` direto em `canca.workspace_scan_intents` para transferir uma intenção do workspace A ao B. O erro SQL esperado é revertido por savepoint, preservando a decisão aprovada e `execution_authorized=false`.

Gate: Workspace Foundation CI e oito workflows obrigatórios. v0.6.75 integrada pelo PR #186. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster permanecem pendentes.
