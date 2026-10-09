# Cancã v0.6.56 — regrant não concede poder de decisão

Teste real PostgreSQL 16/17: uma intenção com decisão `approved` é lida antes e depois da revogação/reconcessão do direito `workspace:read`. O leitor reconcedido não pode consumir a intenção nem modificar decisões; a sequência de decisões permanece idêntica e `execution_authorized=false`.

A aprovação histórica nunca constitui autorização de execução. Executar via `tests/test_workspace_intent_ledger.py` sob Workspace Foundation CI, exigindo oito pipelines aprovados antes do merge. v0.6.55 integrada pelo PR #166. E0, R02/R06, recuperação cross-cluster e maker/checker seguem pendentes.
