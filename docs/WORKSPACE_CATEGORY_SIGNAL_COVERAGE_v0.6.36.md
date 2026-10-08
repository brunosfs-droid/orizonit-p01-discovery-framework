# Cancã v0.6.36 — visão de sinais registrados por categoria

Incremento para futuro inventário e Mapper. Mede apenas **sinais registrados nos objetos cadastrados**, nunca o grau de descoberta dos ativos na rede.

## Contrato HTTP

GET /api/v1/workspaces/{workspace_id}/categories/{category}/signal-coverage?generation=N&expected_revision=R&after=CURSOR&limit=20

Categorias: compute, network, services, components. Filtros: site_id, environment_id, kind e origin. Requer sessão autorizada, workspace aberto, grant workspace:read e revision fence. Continuação após cursor exige expected_revision. O leitor examina no máximo uma página de 100 objetos cadastrados e projeta no máximo 20 objetos filtrados por chamada. Páginas intermediárias podem não conter registros correspondentes e mesmo assim manter next_after.

Cada objeto é consultado pelo model autorizado, com revisão fixada; retorna object_id, kind, origin, observed_kind_count, conflicting_kind_count e observation_status. Sem credenciais, caminhos de evidência, declarações promovidas a observações ou varredura ativa. collection_coverage=not_assessed e absence_implies_missing=false são invariantes.

O audit registra apenas a operação category_signal_coverage. Testes unitários de paginação/isolation e regressões HTTP/audit estão incorporados à matriz Workspace Foundation CI PostgreSQL 16/17.

**Gates separados:** CI e revisão do PR; merge; posterior CI da main; homologação EVE-NG e Product Alpha. Não fechar R03–R06 pelo simples sucesso dos testes.
