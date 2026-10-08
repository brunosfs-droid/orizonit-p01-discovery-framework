# Cancã v0.6.33 — resumo de sinais efetivamente observados

## Entrega candidata

Consulta de atributo por objeto, construída a partir do histórico de observações persistidas da v0.6.32. Para cada tipo de sinal, apresenta valores da data de recebimento mais recente **na ordem garantida pelo reader SQL** e referências `collection_id`, `ordinal` e `created_revision`. Múltiplos valores em uma mesma época recebem `status=conflicting`, sem decidir automaticamente qual é correto. Um único valor recebe `status=observed`.

GET `/api/v1/workspaces/{workspace_id}/objects/{object_id}/signals/summary?generation=N&expected_revision=R`

Acesso pela mesma sessão/grant `workspace:read`, coordenador aberto e revision fence do modelo. O audit usa somente operação `signal_summary` (sem IDs/caminhos/query). Não mistura declarações do operador, não expõe caminhos das evidências e não afirma o instante de coleta do dispositivo. Nenhuma migração SQL ou coleta ativa.

O leitor falha fechado se o histórico exceder o limite de 100 observações do model, 100 tipos de sinal ou 100 valores distintos por tipo. O limite de 1.000 sinais na validação base permanece obrigatório. Não é inventário completo: ausência de registro não prova ausência de dispositivo ou atributo.

## Qualificação

Suite `tests/test_workspace_signal_summary.py` cobre valores do último lote, conflitos, proveniência, ausência de declarações, limites e segregação entre workspaces. API HTTP e auditoria possuem regressões próprias; Workspace Foundation CI executa os novos casos na matriz PostgreSQL 16/17.

## Gates separados

CI do último commit, revisão/merge e estado pós-merge da main são obrigatórios para encerrar este incremento técnico. Validação EVE-NG (import de pacotes, restore, isolamento, atributos reais) e Product Alpha continuam abertas, sem promoção automática por CI.
