# Cancã — Workspace Foundation v0.6.21

**CANDIDATE, opt-in, para base isolada de desenvolvimento.** A fundação implementa
registry, grants por SQL-role, sites, ambientes opcionais e mapping explícito de
assessment. Ainda não apresenta UI/Mapper ou carrega inventário de workspace.
[ADR 0037](ADR_0037_Workspace_Foundation_v0.6.21.md) · [Plano](IMPLEMENTATION_PLAN_1.0.md) ·
[Qualificação CI](validation/WORKSPACE_FOUNDATION_CI_v0.6.21.md).

## Modelo

| Tabela | Responsabilidade |
|---|---|
| workspaces | ID estável, nome/organização e data; registry leve. |
| workspace_grants | Workspace + role PostgreSQL + read/write; default deny. |
| workspace_sites | Site da base, nome/tipo/parent; chave/FK compostas. |
| workspace_environments | Produção/Homologação/LAB/Other opcionais na base. |
| workspace_assessments | Mapping administrativo único de assessment legado; sem backfill de assets. |

IDs têm 1–128 caracteres ASCII `[A-Za-z0-9._-]`, primeiro alfanumérico. Nomes
UTF-8 têm 1–255 caracteres, sem controles/whitespace externo. Organização pode
ser vazia. Nomes não são paths nem decisões de identidade. Sites: on_premises,
remote, azure, aws, cloud ou other. Ambientes: production, homologation, lab, other.

## Provisionamento de teste

Python/driver PostgreSQL existentes; PG16/17. A CLI usa o mesmo libpq/config/TLS
da fundação atual. Não passar DSN/senha em argumentos. Identidade de conteúdo
é o role da conexão, diferente de login Cancã, credenciais de alvos e mTLS Node.

Estas operações destinam-se ao ambiente dedicado; nenhuma é solicitada ao
mantenedor agora. Schema 5 recusa readers 1–4, e não deve ser aplicado ao banco
do LAB operacional com a Web atual. Sem downgrade automático; retorno após commit
exige restore qualificado do par banco/store/config anterior.

Com DB maintenance identity explicitamente autorizada para DDL/BYPASSRLS:

```sh
python persistence/P01_Workspace.py migrate
python persistence/P01_Workspace.py create-workspace --workspace-id LAB-A --name "LAB A"
python persistence/P01_Workspace.py create-workspace --workspace-id LAB-B --name "LAB B"
python persistence/P01_Workspace.py grant-workspace --workspace-id LAB-A --principal-role canca_lab_writer --permission workspace:write
```

O administrador cria os roles SQL e concede privileges separadamente. Exemplo
para um role de aplicação já existente, NOSUPERUSER/NOBYPASSRLS, sem ownership/DDL:

```sql
GRANT USAGE ON SCHEMA canca TO canca_lab_writer;
GRANT SELECT ON canca.schema_migrations,canca.workspaces,canca.workspace_grants,
    canca.workspace_sites,canca.workspace_environments,canca.workspace_assessments
    TO canca_lab_writer;
GRANT INSERT ON canca.workspace_sites,canca.workspace_environments TO canca_lab_writer;
```

Um reader recebe apenas USAGE/SELECT e workspace:read. Grantee sem role existente,
superuser ou BYPASSRLS é rejeitado. Não conceder tabelas legadas à role nova.
Membership/SET ROLE e autenticador DB são controlados pelo administrador; SQL RLS
não protege contra superuser, alteração de schema/policy ou membership indevida.

Conectado como a role de aplicação com grant LAB-A:

```sh
python persistence/P01_Workspace.py list-workspaces
python persistence/P01_Workspace.py create-site --workspace-id LAB-A --site-id matriz --name Matriz --kind on_premises
python persistence/P01_Workspace.py create-site --workspace-id LAB-A --site-id azure --name Azure --kind azure --parent-site-id matriz
python persistence/P01_Workspace.py create-environment --workspace-id LAB-A --environment-id producao --name Producao --kind production
python persistence/P01_Workspace.py list-items --workspace-id LAB-A --category sites --limit 100
```

Sites e ambientes são conceitos separados e pertencem diretamente ao workspace.
Não há carregamento de todos os dados do registry: lists são páginas de até 100
metadados com `next_after` e `has_more`. IDs A/B iguais são independentes.

## Migração e decisões administrativas

Migração 0005 é a única mudança DDL; 1–4 permanecem byte a byte/checksums. Migrate
default continua em 4. Opt-in inclui prefixo 1–5, replay/checksum e uma transação.
Não modifica assessments, runs, assets, findings, recibos ou store.

Com maintenance identity, mapear um assessment existente explicitamente:

```sh
python persistence/P01_Workspace.py bind-assessment --workspace-id LAB-A --assessment-id LAB-001
python persistence/P01_Workspace.py revoke-workspace --workspace-id LAB-A --principal-role canca_lab_writer --permission workspace:write
```

Mapping não dá permissão, projeta inventário ou altera bytes. Assessment ausente
falha; reassignment a outra base falha; replay conserva mapping. Sem update/delete
de ownership. Nenhum realm/CIDR/workspace ativo infere essa decisão. IDs legados
globais não ganham namespaces por este mapping: isso pertence à migração completa.

## Segurança, replay e erros

- SQL-role current_user + grant, nunca principal livre no GUC. RLS forçada em
  tabelas novas; sites/ambientes/mapping requerem contexto de workspace da transação.
- SET LOCAL/contexto restaurado; transaction caller em andamento é rejeitada,
  sem commit de trabalho do caller. SQL fault reverte dados/contexto.
- Scope não concede permissões. GUC forjado para B não habilita read/write.
- Registry autorizado somente nomes/IDs; DB admin não ganha read grant na CLI.
- Create/replay iguais retornam registered/already_registered; conflito falha
  sem overwrite. Grants/mapping/revogações têm replay próprio.
- Erro CLI retorna JSON com código fixo, exit 2; não imprime driver/DSN/secret/path.
  Sucesso exit 0. Denied workspace inexistente ou alheio usa workspace_access_denied.
- A hierarquia append-only exige parent na mesma base já existente; self/ciclo/
  parent externo são rejeitados também em SQL. Aplicação não recebe UPDATE/DELETE.

## Qualificação e próximo incremento

`tests/test_postgres_workspace.py` roda contratos puros sem DB e integração quando
`CANCA_TEST_WORKSPACE_POSTGRES=1`; esta opção apaga o schema canca no banco de teste.
Workflow Workspace Foundation CI usa containers dedicados PG16/17, 18 casos sem
skips. CI legado mantém seu schema4/recovery e não ativa workspaces.

[v0.6.22](WORKSPACE_COORDINATOR_v0.6.22.md) acrescenta coordenador lógico de carga
única, lease/generation/drain/cache em schema6 opt-in separado. A fundação pode
ler 5/6 após checksum; seu migrator continua no prefixo 1–5 e rejeita 6.
UI/API/inventário/jobs legados ainda não integrados.
Depois seguem observações/identidade, relações, reconciliação/import e migração
completa/API. LAB/restore5/produção não são qualificados por contratos sintéticos.
