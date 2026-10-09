# Cancã v0.6.58 — isolamento e geração após troca A→B→A

Teste PostgreSQL 16/17 de troca de workspace aberto: uma intenção aprovada em A não é visível em B; ao reabrir A com nova geração/lease, seu histórico reaparece apenas como evidência, com `context_current=false` e `execution_authorized=false`. Uma tentativa de consumir a aprovação antiga deve ser rejeitada com `intent_stale`.

Gate no `tests/test_workspace_intent_ledger.py` com oito workflows obrigatórios antes de merge. v0.6.57 integrada pelo PR #168. E0/EVE-NG, R02/R06, cross-cluster e maker/checker continuam pendentes.
