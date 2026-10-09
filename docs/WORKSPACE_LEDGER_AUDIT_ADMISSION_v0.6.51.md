# Cancã v0.6.51 — auditoria fail-closed na admissão HTTP

Teste adversarial no endpoint GET de histórico do ledger. Quando o sink de
arquivo privado recusa iniciar uma operação (por exemplo, indisponibilidade
ou falta de capacidade), o servidor responde HTTP 503
`workspace_audit_unavailable` e não chama o backend.

O teste restaura o sink e comprova que uma nova solicitação autenticada
retorna somente histórico não executável. A simulação isola a falha de
admissão, sem modificar arquivos reais ou suprimir trilha de auditoria.

Executar em CI com `test_workspace_live_intent_http.py`; os jobs Python e
Workspace Foundation oferecem o gate. A v0.6.50 foi integrada no PR #161.
Não fecha EVE-NG, R02/R06, identidade maker/checker nem restauração
cross-cluster. Não habilita scanner, coleta de credenciais ou execução.
