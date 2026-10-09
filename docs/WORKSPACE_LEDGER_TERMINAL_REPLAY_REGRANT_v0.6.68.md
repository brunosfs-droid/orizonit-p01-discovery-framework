# Cancã v0.6.68 — replay terminal idempotente após regrant

Teste PostgreSQL 16/17: após `approved` → `consumed`, a revogação/reconcessão do direito `workspace:read` não altera a semântica de idempotência. Repetir `consumed` com o mesmo `request_id` retorna `replayed=true`, sem acrescentar decisões; a sequência permanece `[1,2]` e nenhuma execução ou atividade de rede é autorizada.

Gate: `tests/test_workspace_intent_ledger.py` sob Workspace Foundation CI e oito workflows antes do merge. v0.6.67 integrada pelo PR #178. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker permanecem pendentes.
