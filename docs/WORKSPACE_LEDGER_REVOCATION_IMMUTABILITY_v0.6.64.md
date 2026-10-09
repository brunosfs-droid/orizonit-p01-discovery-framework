# Cancã v0.6.64 — imutabilidade do histórico após revogação

Teste PostgreSQL 16/17: decisão `approved` gravada em workspace A permanece inalterada quando o acesso `workspace:read` de uma role é revogado. O leitor revogado perde acesso; outra role autorizada verifica que o histórico mantém as mesmas decisões, sempre com `execution_authorized=false`.

Gate: `tests/test_workspace_intent_ledger.py` e Workspace Foundation CI, além dos oito workflows antes de integrar. A v0.6.63 foi integrada pelo PR #174. E0/EVE-NG, R02/R06, recuperação cross-cluster e maker/checker continuam pendentes.
