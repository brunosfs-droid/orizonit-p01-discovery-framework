# Cancã v0.6.55 — reativação controlada de leitura histórica

Teste PostgreSQL real (16/17) da sequência concessão → revogação → nova concessão `workspace:read`. Após revogação, a role deixa de acessar o histórico; após regrant, pode ler novamente o mesmo registro, sem executar varreduras ou alterar decisões (`execution_authorized=false`, `network_activity_performed=false`).

A qualificação cobre somente o contrato SQL de leitura e não habilita execução. A v0.6.54 foi integrada pelo PR #165. E0/EVE-NG, R02/R06, recuperação cross-cluster e identidade maker/checker permanecem pendentes.
