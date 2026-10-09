# Cancã v0.6.48 — histórico HTTP auditado do ledger

Rota exclusivamente de leitura: `GET /api/v1/workspaces/{workspace_id}/scan-intents/{intent_id}?generation={n}`.

A sessão local deve estar autenticada e vinculada a uma role SQL. O serviço exige
`workspace:read`, geração/lease ativos e políticas RLS do schema10.
Apenas identificadores `intent-[0-9a-f]{32}` são aceitos; não existe endpoint
HTTP para registrar, aprovar, consumir ou executar intenções. Retorna histórico
com `execution_authorized=false`, inclusive após restore/restart.

A rota exige auditoria privada disponível (fail-closed). O classificador registra
somente a operação `scan_intent_history`, sem intenção, query, credenciais ou
identificadores de rota. Parâmetros permitidos: apenas `generation` obrigatório;
qualquer duplicação ou parâmetro adicional é rejeitado.

Testes: `python -m unittest discover -s tests -p 'test_workspace_live_intent_http.py' -v`
mais `test_workspace_intent_ledger.py` PG16/17 em CI. Nenhuma execução no EVE-NG.

Limites: autenticação local não constitui identidade humana maker/checker. A
auditoria é arquivo privado e não SIEM imutável. R02/R06, E0, cross-cluster,
restauração de TLS/secrets e homologação Product Alpha continuam pendentes.
