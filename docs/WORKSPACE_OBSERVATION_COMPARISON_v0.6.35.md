# Cancã v0.6.35 — comparação de observações persistidas

Incremento read-only sobre o histórico de sinais observado e revision-fenced das v0.6.32–34. Exibe, **por tipo de atributo**, dois grupos de valores de datas de **recebimento no servidor** distintas: o mais recente e o anterior em que aquele tipo apareceu. Não executa scans, não calcula divergência de configuração de máquinas, não interpreta timestamps como horários de coleta e não promove atributos declarados.

## Contrato HTTP

`GET /api/v1/workspaces/{workspace_id}/objects/{object_id}/signals/comparison?generation=N&expected_revision=R`

Sessão local autorizada, workspace aberto, grant `workspace:read`, revisão do objeto e checagens pós-operação do coordenador. Resposta com `comparison=insufficient_history|same_recorded_values|different_recorded_values` por tipo de sinal. Valores de cada época incluem `collection_id`, `ordinal`, `created_revision` e indicação booleana de existência de referência de origem. `source_refs` brutos/caminhos privados não são expostos. Campos `drift_assessed=false`, `absence_implies_missing=false` e `collection_time_known=false` previnem interpretações incorretas.

Pelo contrato do modelo, o histórico completo só é acessível dentro do limite de 100 observações por objeto. Exceder o limite falha explicitamente; sem provas de duas datas, devolve `insufficient_history`. No máximo 100 tipos, 100 valores distintos por período e 1.000 sinais avaliados. Não há migração SQL, credenciais novas ou conexão externa.

## Qualificação e gates

`tests/test_workspace_observation_comparison.py`, suite HTTP e auditoria verificam isolamento, revisão, proveniência, conflitos, múltiplas páginas, redaction e ausência de provas indevidas. Workspace Foundation CI executa os testes na matriz PostgreSQL 16/17.

**Estado inicial:** candidata na branch feature/workspace-observation-comparison-v0.6.35. Apenas integrar após CI completo, revisão e merge; EVE-NG e Product Alpha permanecem gates abertos e separados.
