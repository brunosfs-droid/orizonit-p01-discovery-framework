# Cancã v0.6.49 — proteção contra regressão nas rotas HTTP

A introdução da leitura auditada do histórico do ledger em v0.6.48 exige
compatibilidade explícita com os identificadores de rotas legadas.

## Gate

- A rota de leitura de intenção continua usando o grupo de captura 6
  (`intent-[0-9a-f]{32}`).
- As rotas de relatório e readiness legados continuam usando o grupo 5
  (`bnd-[0-9a-f]{20}`).
- A auditoria classifica a leitura como `scan_intent_history`, nunca
  classifica métodos mutáveis como operação válida para esse endpoint.
- Sem auditoria privada, GET de histórico é negado antes de chamar o serviço.
  POST, PUT, PATCH e DELETE não podem produzir transições via HTTP.

Teste em `tests/test_workspace_live_intent_http.py`, no CI Python e Workspace
Foundation existente (PostgreSQL 16/17 para os demais testes de isolamento).

Nenhuma nova migração, escrita, scanner, credencial, coleta ou atuação no
EVE-NG. R02/R06 e E0 continuam pendentes. O gate protege a compatibilidade
conquistada nos PRs #159 e anteriores, não substitui validação operacional.
