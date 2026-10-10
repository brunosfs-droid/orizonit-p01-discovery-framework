# Cancã v0.6.79 — isolamento A-B-A após reconcessão de leitura

Teste PostgreSQL 16/17: após revogar e reconceder a leitura no workspace A, a role leitora mantém acesso ao histórico autorizado em A, não pode consultá-lo no contexto B e recupera apenas o mesmo histórico ao voltar ao contexto A. O histórico permanece não executável.

Gate: Workspace Foundation CI e oito workflows obrigatórios antes de merge. A v0.6.78 foi integrada pelo PR #189. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster continuam pendentes.
