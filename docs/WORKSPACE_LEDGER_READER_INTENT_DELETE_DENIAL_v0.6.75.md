# Cancã v0.6.75 — negação de exclusão direta de intenção pelo leitor

Teste PostgreSQL 16/17: após revogação e reconcessão de `workspace:read`, uma role leitora não pode executar `DELETE` direto em `canca.workspace_scan_intents`. A falha esperada é revertida por savepoint, preservando a intenção e sua decisão `approved`, sem autorizar execução.

Gate: Workspace Foundation CI e oito workflows obrigatórios. v0.6.74 integrada no PR #185. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster seguem pendentes.
