# Cancã — Workspace API v0.6.26

CANDIDATE opt-in em schema7 isolado. Listener humano separado na porta8879 por
default; não substituir o operador legado em schema4. [ADR0040](ADR_0040_Workspace_API_v0.6.26.md).

## Rotas

| Método e rota /api/v1 | Entrada principal |
| --- | --- |
| POST operator/session | username/password; retorna bearer opaco. |
| DELETE operator/session | Authorization: Bearer; encerra sessão. |
| GET workspaces | after/limit; bases autorizadas e metadados de ciclo. |
| POST workspaces/{id}/open | generation atual do registry. |
| POST workspaces/{id}/close | generation e timeout opcional0–30. |
| GET workspaces/{id}/objects | generation obrigatório; after/limit/expected_revision. |
| GET workspaces/{id}/objects/{object} | generation e expected_revision opcional. |
| GET workspaces/{id}/graph/{object} | generation, expected_revision, depth/node_limit/edge_limit opcionais. |
| POST workspaces/{id}/objects | generation, expected_revision, request_id, object_id, kind, label, reason; atributos/site/ambiente opcionais. |
| POST workspaces/{id}/declarations | generation, expected_revision, request_id, object_id, name/value/reason. |
| POST workspaces/{id}/relationships | generation, expected_revision, request_id, relationship_id, source/target_id, kind/reason; active opcional. |
| POST workspaces/{id}/imports/preview | generation, assessment_id/bundle_id; mode/categories/decisions/site/ambiente opcionais. |
| POST workspaces/{id}/imports/apply | generation, plan_id, request_id. |

`GET /healthz` informa versão sem conteúdo. Requests nunca aceitam db_role,
lease_id, path ou DSN. Decisões de prévia usam chaves JSON ordinais canônicas
"0"–"999", convertidas para inteiros internamente. Nenhum import ocorre ao abrir
workspace; nenhuma coleta é executada. [Modelo/limites](WORKSPACE_MODEL_v0.6.25.md).

Erros: 401 sessão ausente/expirada, 403 grant/origem negados, 400 input, 404 rota ou
objeto/plano, 409 geração/revisão/drift/busy/review pendente, 503 backend indisponível.
Não repetir automaticamente um apply com outro request_id após resposta perdida;
reconciliar o recibo usando o mesmo payload/ID. Reinício inicia closed e exige open
explícito. Binding/contas são snapshots privados, alterados por restart controlado.

## Configuração interna

Exemplo estrutural (sem credenciais; nomes somente ilustrativos):

```json
{
  "binding_version": "1",
  "coordinator_role": "canca_coordinator",
  "bindings": [{"operator_id": "OP-01", "db_role": "canca_operator01"}],
  "sources": {"LAB": "/srv/canca/workspaces/LAB/store"}
}
```

Arquivo privado0600, regular, owner confiável e path canônico sem symlink.
AccountPolicy v1 existente pode conter grants de assessment vazios; autorização
workspace vem exclusivamente das roles/grants SQL. Um operador não vinculado
consegue autenticar, mas não acessar a API de conteúdo. Source roots existentes e
disjuntos, configurados pelo administrador, não pela requisição.

Provisionar previamente schema7 e roles/grants conforme foundation/model. Broker
LOGIN sem privilégios administrativos, com membership/SET ROLE somente nos atores
e coordenador necessários. Atores não recebem membership no broker/coordenador.
Segredos em configuração externa libpq/PGPASSFILE, nunca args/política/bundle.
Role de manutenção não serve para iniciar o listener.

```sh
python server/P01_Workspace_API.py --accounts /private/accounts.json --bindings /private/workspace-bindings.json
```

Somente exemplo para base de desenvolvimento; não é pedido de execução no LAB.
Remoto requer --tls-cert/--tls-key, IPv4 e Host direto; proxy e pool transacional
não são qualificados. A conexão física do coordenador é dedicada e permanece até
server_close. Startup rejeita schema anterior ou coordenador já ativo. Encerramento
aguarda workers, drena o coordenador e libera a sessão; erro de shutdown é reportado.

## Próximos gates

Migração/restore7 e reports por revisão; UI workspace/Mapper; metadados de sites e
administração com contratos próprios; audit HTTP workspace. Testes sintéticos não
comprovam suporte de vendor/EVE-NG, Windows nativo ou capacidade de produção.
