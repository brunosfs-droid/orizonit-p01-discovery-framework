# Cancã v0.6.59 — token antigo não consulta histórico após A–B–A

Teste integrado PostgreSQL 16/17: após encerrar A, abrir e encerrar B e reabrir A, uma lease/token da geração anterior não pode consultar o histórico; somente a lease atual obtém as evidências, sempre com `context_current=false` e `execution_authorized=false`.

Gate em `tests/test_workspace_intent_ledger.py` sob Workspace Foundation CI e os oito workflows. v0.6.58 integrada pelo PR #169. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker seguem pendentes.
