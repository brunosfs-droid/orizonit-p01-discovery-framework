# Cancã v0.6.34 — diagnóstico limitado de qualidade de sinais

Incremento sobre as leituras autorizadas v0.6.32 e v0.6.33. Disponibiliza GET /api/v1/workspaces/{workspace_id}/objects/{object_id}/signals/quality?generation=N&expected_revision=R sob a mesma permissão workspace:read.

Os diagnósticos são exclusivamente derivados de observações persistidas: quantidade de tipos observados, tipos em conflito, valores distintos e número de referências de proveniência por tipo. Não inferem ausência física de ativos, completude de coleta, credibilidade do dado, saúde do equipamento nem instante de coleta. Caminhos de arquivos, declarações manuais e identificadores de recursos não entram no log de auditoria.

Limites fail-closed: até 100 tipos, 100 valores por tipo e 1.000 referências por tipo, respeitando o reader base. Nenhuma migração SQL e nenhuma coleta ativa. API, auditoria e testes unitários adicionados ao Workspace Foundation CI PostgreSQL 16/17.

## Gates
Qualificar todos os workflows no commit final do PR, revisão e merge posterior. Homologação operacional EVE-NG, recovery end-to-end e Product Alpha permanecem abertos.
