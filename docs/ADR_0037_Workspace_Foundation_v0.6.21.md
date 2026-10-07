# ADR 0037 — fundação opt-in de workspaces v0.6.21

Data: 07/10/2026 (-03). Decisão de implementação aceita. Estado: CANDIDATE.
Implementa o primeiro incremento da [ADR 0036](ADR_0036_Workspace_First_1.0.md).

## Decisão e fronteira deste incremento

Adicionar migração 0005 e CLI independente para registro de workspaces, sites,
ambientes, grants e mapping explícito de assessments existentes. Schema 1–4,
collectors, bundles/store, contas humanas e APIs atuais permanecem em seus contratos.
`P01_PostgreSQL.py migrate` aplica somente 1–4. `P01_Workspace.py migrate` escolhe
1–5 explicitamente. Nenhuma operação de startup aplica DDL ou associa dados.

Depois de optar pelo schema 5, readers/indexers legados rejeitam `schema_mismatch`
antes de conteúdo: não devem consumir a base nova sem adaptação de contexto/grants.
Usar base isolada para qualificar a fundação. Este incremento não é upgrade
operacional da Web atual. Migração completa de inventário/histórico e compatibilidade
dos relatórios pertencem aos próximos incrementos. Não habilitar no LAB atual agora.

## Identidade, autorização e RLS

Grants de conteúdo são vinculados a `current_user`, identidade autenticada pelo
PostgreSQL. Não aceitar operador/principal por variável de contexto enviada pelo
cliente. SQL-role diferente não recebe conteúdo mesmo se alterar `canca.workspace_id`.
`workspace:write` inclui leitura necessária para cadastro; `workspace:read` é
somente leitura. Privilegiar DB e ter grant de produto são controles distintos.

RLS habilitada e forçada nas cinco tabelas novas. Registry expõe somente IDs/nomes
de bases permitidas, sem carregar inventários. Sites/ambientes/mapping exigem
contexto transacional e grant; contexto é restaurado e erro SQL faz rollback.
Roles de aplicação recebem SELECT e, quando necessário, INSERT apenas em sites/
ambientes. Sem UPDATE/DELETE/grant/ownership por aplicação.

Manutenção de registry/grants/ownership exige uma identidade DB administrativa
com superuser/BYPASSRLS e SQL privileges explícitos; não é o papel humano de
administração do servidor. Não conceder conteúdo via grants a superuser/BYPASSRLS.
Essas identidades DB são parte do domínio de confiança de manutenção: podem
administrar o banco e não são isoladas contra acesso SQL privilegiado. Mesmo para
elas os readers da CLI não presumem grant de conteúdo. Adaptador Web/autenticação
por operador ainda não existe; não usar um único role compartilhado como múltiplos
usuários humanos. A futura API deve preservar a identidade/grants autorizados.

Chaves compostas permitem mesmo site/environment ID em bases diferentes. Parent
site usa workspace na FK. Hierarquia é append-only pela aplicação; trigger exige
parent já existente e rejeita ciclos em multi-row INSERT. Nenhuma referência a
site de outra base. Assessment legado globalmente identificado recebe mapping
único e imutável; não copiar bytes, inferir organização ou fundir assets.

## Transações e compatibilidade

Migração conserva checksums 0001–0004, aplica 0005 atomicamente e rejeita drift.
Failure rollback preserva schema anterior. Registry/site/environment usam lock
por identidade, replay idempotente e conflito explícito sem overwrite. Mapping de
assessment usa lock próprio; reatribuição a outra base falha. Grants/revogações
são idempotentes, consultados nas novas operações e nas políticas SQL.

Load/open/close/lease/generation será v0.6.22. A CLI atual administra metadados,
não abre grafo ou segundo contexto residente. Sem grafo/Mapper, scan, interface de
import ou coleta Graph nesta fundação. Asset/run/source passam para ownership
completo nos incrementos posteriores; RLS não foi aplicada às tabelas legadas.
Roles novas não recebem SQL privileges nelas e readers legados recusam schema 5.

## Validação

Suite dedicada PostgreSQL 16/17, isolada dos testes/destrutivos da base 1–4:
entrada/redação, mesmo ID A/B, GUC forjado, SQL RLS, privilege denial, hierarquia,
revogação, mapping, preservação de evidência/rows, concorrência, rollback e caller
transaction. Gates operacionais/LAB, restore do schema 5, roles/TLS de produção,
API humana e migração completa permanecem separados. [Contrato](WORKSPACE_FOUNDATION_v0.6.21.md).
