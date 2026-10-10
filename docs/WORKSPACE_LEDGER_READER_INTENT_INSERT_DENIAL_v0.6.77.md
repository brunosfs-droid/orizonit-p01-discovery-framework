# Cancã v0.6.77 — negação de INSERT direto em intenções por leitor

Teste PostgreSQL 16/17: após revogar e reconceder `workspace:read`, a role de leitura não pode executar INSERT direto em `canca.workspace_scan_intents`. O erro SQL esperado é isolado por savepoint; a intenção anterior e a decisão `approved` permanecem íntegras e não executáveis.

Gate: Workspace Foundation CI e oito workflows obrigatórios. v0.6.76 integrada pelo PR #187. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster permanecem pendentes.
