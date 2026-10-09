# Cancã v0.6.52 — confidencialidade de auditoria do histórico HTTP

O teste de integração HTTP confirma que a leitura autenticada de decisões do ledger gera somente a classificação estática `scan_intent_history` no arquivo privado de auditoria. O identificador da intenção, a rota literal, os campos da query e valores sensíveis não são gravados no log.

O resultado do endpoint permanece apenas histórico (`execution_authorized=false`), sem permissão de executar scanners ou criar transições.

Gate: `tests/test_workspace_live_intent_http.py` em Python CI e Workspace Foundation CI; merge condicionado aos oito workflows. A v0.6.51 foi integrada via PR #162.

Pendências preservadas: E0/EVE-NG, R02/R06, cross-cluster, maker/checker humano e homologação Product Alpha.
