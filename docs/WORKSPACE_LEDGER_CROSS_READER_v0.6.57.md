# Cancã v0.6.57 — isolamento de leitores do histórico entre workspaces

Novo teste PostgreSQL 16/17: a intenção do workspace A contém uma decisão `approved`, visível ao leitor de A. Após a troca do workspace aberto para B, nem o leitor de B nem a role escritora autorizada para B conseguem recuperar a intenção originada em A. Espera-se `intent_not_found`, sem acesso cruzado ou qualquer autorização de execução.

Gate: `tests/test_workspace_intent_ledger.py` no Workspace Foundation CI e aprovação dos oito workflows do PR antes do merge. v0.6.56 integrada pelo PR #167. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker continuam pendentes.
