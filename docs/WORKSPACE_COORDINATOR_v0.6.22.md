# Cancã — Workspace Coordinator v0.6.22

**CANDIDATE opt-in, base isolada de desenvolvimento.** Fundação programática de
carga única; ainda sem UI/API, inventário carregado ou alteração do LAB operacional.
[Decisão](ADR_0038_Workspace_Coordinator_v0.6.22.md) · [Plano](IMPLEMENTATION_PLAN_1.0.md).

## Contrato

| Operação | Efeito e autorização |
| --- | --- |
| start | Serviço confiável adquire lease exclusivo; nova generation/closed, sem replay live. |
| open | Ator com workspace:read e generation atual; ativa contexto lógico. Mesma base/revisão tem replay; outra base é busy. |
| borrow | Grant atual read/write e token exato; registra um job dentro de contexto Python. |
| Operation.check | Revalida grant, lease, generation e registro ativo; chamar antes de publicar resultado. |
| cache_get/cache_put | Revalidam os mesmos controles; keys de ID e values bytes imutáveis. |
| close | Ator com workspace:write e generation esperada; cancelamento, drain, cache livre, closed. |
| snapshot | Metadados do ciclo; se há workspace aberto/closing, exige read desse workspace. Não revela ID de outra base. |
| shutdown | Ciclo interno de processo confiável; drena e fecha sessão. Não é endpoint de operador. |

Token tem workspace_id, generation e lease_id. Não é credencial; toda operação
precisa de conexão do ator com grant. Um actor connection não pode ser usado por
jobs concorrentes: cada request/trabalho tem conexão própria e não pooled entre
identidades. A conexão do lease é física, dedicada, sem uso externo e pertence ao
coordenador. Multiworker futuro deve delegar ao único coordenador da instalação;
iniciar coordenador por worker produz busy, não um segundo contexto.

## Limites e erros

Defaults: 16 jobs, 64 entradas de cache, 8 MiB de values totais, 1 MiB por entrada.
Teto configurável: 256 jobs, 4.096 entradas, 64 MiB totais, 8 MiB por entrada.
Contadores medem payload, não todo overhead Python. Rejeição de tamanho/quantidade
conserva valores antigos; substituir uma entrada atualiza a contagem. Cache é
privado ao contexto lógico, liberado após drain, sem persistência/import implícito.

Heartbeat default um segundo; fence também é verificado em cada operação.
Timeout de drain default cinco segundos, intervalo aceito 0–30, por relógio
monotônico. Esse prazo limita a espera de jobs, não o tempo total de I/O SQL;
transações SQL usam os limites existentes (lock 5s, statement 30s).

| Código | Conduta |
| --- | --- |
| workspace_runtime_busy | Outro coordenador/base ou encerramento ativo; não abrir automaticamente. |
| workspace_generation_stale | Pedido/token/job antigo ou operação já encerrada; descartar resultado. |
| workspace_close_pending | Jobs não drenaram no prazo; conservar closing/lease e tentar close com a generation atual após conclusão. |
| workspace_lease_lost | Contexto indisponível/recovery_required; cancelamento e nenhum novo open nesse objeto. |
| workspace_jobs_full / workspace_cache_full | Limite atingido; não remover trabalho/valor existente. |
| workspace_runtime_not_provisioned | Role/linha de serviço ainda não provisionada. |
| workspace_connection_mismatch | Conexão do ator pertence a outro endpoint/banco; rejeitar antes dos grants. |
| workspace_access_denied | Grant ausente ou revogado; sem fallback para workspace ativo. |

Close exige workspace ID explícito. Uma aba atrasada não fecha o workspace que
outra abriu. Nunca finalizar um job à força para trocar de base. Import em commit
futuro precisa registrar sua intenção e concluir/reconciliar antes do drain.

## Provisionamento dedicado

Estas instruções não solicitam ação do mantenedor agora. Com DB maintenance
identity autorizada para DDL/BYPASSRLS, somente em banco isolado:

```sh
python server/P01_Workspace_Coordinator.py migrate
python server/P01_Workspace_Coordinator.py provision-runtime --principal-role canca_coordinator
```

Criar antes a role de serviço, com autenticação externa ao programa:

```sql
CREATE ROLE canca_coordinator LOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA canca TO canca_coordinator;
GRANT SELECT ON canca.schema_migrations TO canca_coordinator;
GRANT SELECT,UPDATE ON canca.workspace_runtime TO canca_coordinator;
```

Sem senha/DSN em argumentos; mesma configuração libpq/TLS da persistência. Não
conceder tabelas de conteúdo, grant de workspace, ownership, CREATE ou membership
privilegiada à role de serviço. Roles dos atores seguem o provisionamento da
[v0.6.21](WORKSPACE_FOUNDATION_v0.6.21.md). Uma role DB compartilhada não identifica
humanos diferentes; o adapter de autenticação humana ainda será implementado.

Migração runtime aplica/verifica prefixo 1–6. Migração default permanece 1–4,
e a CLI de fundação conserva 1–5; tentar usar esses migrators depois de 6 falha
com schema_mismatch. Readers de fundação podem ler 5/6 após checksum; readers
legados rejeitam ambos. Não reescreve bytes/checksums de migrações 1–5, inventário
ou evidência. Sem downgrade; restore exige par banco/store/config qualificado.

## Uso pelo adapter futuro

```python
from P01_Workspace_Coordinator import Coordinator, SessionLease

coordinator = Coordinator(SessionLease(dedicated_service_connection))
generation = coordinator.start()
token = coordinator.open(actor_connection, 'LAB-A', generation)
with coordinator.borrow(actor_connection, token) as operation:
    operation.cache_put('summary', b'bounded-workspace-metadata')
    operation.check()  # Fence antes de publicar; não substitui fence SQL de commit.
generation = coordinator.close(actor_connection, 'LAB-A', token.generation)
coordinator.shutdown()
```

Atores precisam das permissões da tabela acima; código de integração é confiável.
Endereço libpq, porta e banco do ator devem coincidir com os da conexão do lease.
Endpoint/configuração são confiáveis; aliases diferentes são rejeitados. Não usar
proxy que roteie o mesmo endpoint para bancos/instalações independentes.

O hook authorizer injetável destina-se a testes/adapters qualificados; a instância
normal usa SQL-role/current_user + grants da fundação. Não expor esse hook ao usuário.

## Testes e próximos passos

`test_workspace_coordinator.py`: 17 casos de ciclo/cache/concorrência e nove casos
PostgreSQL opt-in. Workflow Workspace Foundation CI mantém os 18 casos de fundação
em schema5 e acrescenta o coordenador em schema6 nos dois containers PG16/17.
Inclui dois processos/sessões, os._exit, pg_terminate_backend, RLS, grants/revogação,
raw unlock e recuperação em closed sem replay.

Ainda pendentes: integração Web/API, scanner/import/export legado, loader de
inventário, fence transacional de commit, restore6, browser e benchmark de RAM/
latência. R02/T03/T14 completos não são declarados concluídos. Próximo incremento
planejado: v0.6.23, CollectionRun/Observation/Declaration/AssetIdentity.
