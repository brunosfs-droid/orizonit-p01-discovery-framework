# Cancã v0.6.54 — revogação SQL de leitura do histórico

Teste PostgreSQL real (16/17) para revogação de `workspace:read`: um leitor autorizado consulta o histórico do ledger no workspace A; após remover sua concessão SQL, a mesma identidade deixa de consultar o histórico. Outra identidade com concessão preservada continua lendo o mesmo objeto. Nenhuma resposta autoriza execução.

Gate: `tests/test_workspace_intent_ledger.py` nos jobs PostgreSQL do Workspace Foundation CI, além dos oito workflows exigidos para integração. v0.6.53 integrada pelo PR #164. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker ainda pendentes.
