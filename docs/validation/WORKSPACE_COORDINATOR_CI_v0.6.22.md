# Workspace Coordinator v0.6.22 — qualificação CI

Data: 07/10/2026. Status: **CANDIDATE opt-in**; operação em LAB e adapters ainda
pendentes. [PR #134](https://github.com/brunosfs-droid/canca/pull/134).

Fonte executável: `6bcf649a9724509fc4d3012535b8b820fd503b92`.
Tree: `d0911c17594195a7f228f7aa9c7c1a661d53453f`.
Base: `741f48200d7c0f6deec71459f964ab2dbd58a52a`.
O commit seguinte deste registro altera somente documentação.

## Local

- Suíte completa: **687 casos / 524 executados / 163 skips opt-in**, PASS.
- Coordenador: **26 casos / 17 executados / nove skips SQL opt-in**, PASS.
- Compilação, diff check e links/fences dos documentos modificados, PASS.
- Migrações 0001–0005 preservadas byte a byte da base, PASS.
- PostgreSQL local não foi usado como prova. A saída backup_restore_failed no
  teste negativo de restore é esperada; a suíte completa terminou com exit 0.

## PostgreSQL real

Workflow Workspace Foundation CI, Linux/Python 3.12, containers dedicados PG16/17.
Cada job executou **18 casos da fundação em schema5 + 26 casos do coordenador em
schema6, sem skips**, PASS. Logs/etapas dos dois jobs da PR conferidos.

| PostgreSQL | Job da PR | Casos | Skips | Resultado |
| --- | --- | --- | --- | --- |
| 16 | [112749245763](https://github.com/brunosfs-droid/canca/actions/runs/37608344670/job/112749245763) | 44 | 0 | PASS |
| 17 | [112749246076](https://github.com/brunosfs-droid/canca/actions/runs/37608344670/job/112749246076) | 44 | 0 | PASS |

Coordenador: abertura concorrente A/B; replay da mesma base/revisão; token antigo
ou forjado; metadados negados; close com write grant; revogação durante job;
limites de jobs/bytes/entradas e valor preservado; cache/job não reutilizável;
close cooperativo e timeout retendo lease; close concorrente sem alteração de
outra geração; lease perdido; 20 trocas sem cache/job restante; validação e CLI
redigida; conexão de outro endpoint negada antes de grants.

Nove casos SQL: schema6/replay/legado preservado; duas sessões e rejeição de
start reentrante; RLS/SQL privileges/role de serviço sem bypass; grants/revogação
reais; pg_terminate_backend detectado pelo heartbeat; raw unlock com fence;
subprocesso com os._exit e recuperação closed; provisionamento sem reassignment
ou acesso a conteúdo; upgrade6 falho revertido e schema5 ainda utilizável.

As mensagens SQL de rejeição de casos negativos são esperadas, não falhas da
suíte. Nenhum caso acessa dispositivos reais ou executa scan.

## Runs da fonte

**15 runs concluídos com success** na fonte acima: oito pull_request e sete
push, incluindo o rerun de infraestrutura descrito abaixo.

| Workflow | pull_request | push |
| --- | --- | --- |
| Workspace Foundation CI | [37608344670](https://github.com/brunosfs-droid/canca/actions/runs/37608344670) | [37608337777](https://github.com/brunosfs-droid/canca/actions/runs/37608337777) |
| Python CI | [37608344686](https://github.com/brunosfs-droid/canca/actions/runs/37608344686) | [37608337535](https://github.com/brunosfs-droid/canca/actions/runs/37608337535) |
| PostgreSQL CI | [37608344715](https://github.com/brunosfs-droid/canca/actions/runs/37608344715) | [37608337654](https://github.com/brunosfs-droid/canca/actions/runs/37608337654) |
| Operator Accounts CI | [37608344707](https://github.com/brunosfs-droid/canca/actions/runs/37608344707) | [37608337520](https://github.com/brunosfs-droid/canca/actions/runs/37608337520) |
| Operator Web CI | [37608344716](https://github.com/brunosfs-droid/canca/actions/runs/37608344716) | [37608337627](https://github.com/brunosfs-droid/canca/actions/runs/37608337627) |
| Optional Agent CI | [37608344708](https://github.com/brunosfs-droid/canca/actions/runs/37608344708) | [37608337556](https://github.com/brunosfs-droid/canca/actions/runs/37608337556) |
| Read-only SNMP CI | [37608344717](https://github.com/brunosfs-droid/canca/actions/runs/37608344717) | [37608337604](https://github.com/brunosfs-droid/canca/actions/runs/37608337604) |
| CodeQL | [37608344730](https://github.com/brunosfs-droid/canca/actions/runs/37608344730) | — |

O run push Workspace Foundation CI teve falha de infraestrutura na primeira
attempt: job 112749219373 não iniciou PostgreSQL17 devido a respostas unauthorized/
HTTP500 ao docker pull. Nenhum teste executou nesse job. Repetição somente do
job falho, attempt2, passou; PG16 da attempt1 e os dois jobs da PR passaram.
A falha histórica permanece registrada, sem alteração de código para contorná-la.

## Limites

A qualificação cobre contexto lógico/lease/generation, jobs registrados e cache
interno limitado. Não integra Web/API/inventário/scanner/import/export legados,
grants humanos, entregas HTTP ou fence atômico de commits. Código de serviço,
configuração libpq e DB maintenance são confiáveis; não aceitar DSN de usuário
ou proxy que roteie um endpoint entre instalações independentes. Controle da
role de serviço ou de roles privilegiadas está fora da fronteira RLS.

Cancelamento é cooperativo: resultado antigo é rejeitado nos checks, mas não
há término forçado de threads ou recuperação automática de um trabalho vivo.
Session loss não desfaz bytes já entregues. Partição pode manter o lease busy
até PostgreSQL detectar o fim da sessão; não existe takeover por TTL.

20 trocas provam contadores/cache liberados nesse fixture; não são medição de
RAM de inventário/Mapper, capacidade comercial ou p50/p95. Execução nativa do
novo coordenador em Windows, browser/multiaba, restore6, EVE-NG/equipamentos reais
e operação do LAB não foram qualificados. R01/R02/T03/T14 continuam parciais.
Nenhuma ação do mantenedor foi solicitada. Próximo: v0.6.23 observações/identidade.
[Contrato](../WORKSPACE_COORDINATOR_v0.6.22.md).
