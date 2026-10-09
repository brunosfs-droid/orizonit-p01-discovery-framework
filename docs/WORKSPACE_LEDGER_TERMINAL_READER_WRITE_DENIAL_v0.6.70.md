# Cancã v0.6.70 — leitor reconcedido não altera intenção consumida

Teste de integração PostgreSQL 16/17: a intenção registra `approved` → `consumed`; após revogar e reconceder somente `workspace:read`, a role leitora consegue revisar o histórico, mas não consegue registrar nova decisão conflitante. A cadeia original permanece imutável, e `execution_authorized=false`.

Gate: `tests/test_workspace_intent_ledger.py` em Workspace Foundation CI, mais oito workflows antes do merge. v0.6.69 integrada pelo PR #180. E0/EVE-NG, R02/R06, maker/checker e recuperação cross-cluster continuam pendentes.
