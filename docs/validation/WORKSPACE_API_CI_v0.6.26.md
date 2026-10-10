# Workspace API v0.6.26 — qualificação CI

Data: 07/10/2026. **CANDIDATE opt-in**. [PR #136](https://github.com/brunosfs-droid/canca/pull/136).

Fonte: `a311851b61d8f23f2dc64e953ba731fc439bde1b`; tree `82ea27a6fd030013a41aef1c40f027406a72b274`. Base integrada v0.6.25: `3fcd4c7ed00e199b4269dda3c3efffc56a7947d6`. O commit deste registro altera somente documentação.

## Evidência

Local: **750 casos / 558 executados / 192 skips opt-in**, PASS. API dedicada:19 casos,16 executados/três skips SQL, PASS. Compilação/diff check, PASS; schemas1–7 e módulos do operador legado preservados.

PostgreSQL16/17: **107 casos por job, sem skips**, PASS (18 foundation +27 coordinator +30 model +13 service +19 API). Logs dos dois jobs da PR e push conferidos.

| PostgreSQL | Job da PR | Resultado |
| --- | --- | --- |
| 16 | [112779114258](https://github.com/brunosfs-droid/canca/actions/runs/37617448323/job/112779114258) | 107 / zero skips / PASS |
| 17 | [112779113849](https://github.com/brunosfs-droid/canca/actions/runs/37617448323/job/112779113849) | 107 / zero skips / PASS |

API: binding privado/imutável/único, operadores desconhecidos e não vinculados, roles privilegiadas e membership do coordenador negados, conexão fresca/fechada, grant SQL read/write e revogação, HTTP real autenticado, login/logout, supressão após logout concorrente, Host/Origin/Sec-Fetch-Site, framing duplicado/chunked, corpo/tipos/limites/queries, proibição de role/path/lease livres, ordinal canônico de decisão, erros redigidos, schema6 recusado antes de listener e limpeza no startup/server_close. Sem UI/browser novo nesta etapa; HTTP usa cliente real e SQL nos três casos opt-in.

## Runs da fonte

15 runs concluídos com success:

| Workflow | pull_request | push |
| --- | --- | --- |
| Workspace Foundation CI | [37617448323](https://github.com/brunosfs-droid/canca/actions/runs/37617448323) | [37617440149](https://github.com/brunosfs-droid/canca/actions/runs/37617440149) |
| CodeQL | [37617448406](https://github.com/brunosfs-droid/canca/actions/runs/37617448406) | — |
| Python CI | [37617448368](https://github.com/brunosfs-droid/canca/actions/runs/37617448368) | [37617440131](https://github.com/brunosfs-droid/canca/actions/runs/37617440131) |
| PostgreSQL CI | [37617448340](https://github.com/brunosfs-droid/canca/actions/runs/37617448340) | [37617440209](https://github.com/brunosfs-droid/canca/actions/runs/37617440209) |
| Operator Web CI | [37617448230](https://github.com/brunosfs-droid/canca/actions/runs/37617448230) | [37617440194](https://github.com/brunosfs-droid/canca/actions/runs/37617440194) |
| Read-only SNMP CI | [37617448228](https://github.com/brunosfs-droid/canca/actions/runs/37617448228) | [37617440228](https://github.com/brunosfs-droid/canca/actions/runs/37617440228) |
| Operator Accounts CI | [37617448342](https://github.com/brunosfs-droid/canca/actions/runs/37617448342) | [37617440176](https://github.com/brunosfs-droid/canca/actions/runs/37617440176) |
| Optional Agent CI | [37617448442](https://github.com/brunosfs-droid/canca/actions/runs/37617448442) | [37617440207](https://github.com/brunosfs-droid/canca/actions/runs/37617440207) |

## Limites

Login humano e conteúdo workspace são opt-in em DB isolado; broker/configuração confiáveis. Sessão é verificada na admissão e entrega, sem rollback retroativo de commit. Recibos/generation reconciliam resposta perdida. Contas/bindings não fazem hot reload; SQL grants são revalidados. Autoria e recibos SQL não equivalem a audit HTTP workspace completo. Não qualifica backfill, restore7, reports/jobs legados, UI/Mapper, Windows nativo, endpoints remotos reais, benchmarks ou vendor/EVE-NG. Nenhuma alteração operacional no LAB. R06/Alpha permanecem parciais.
[Contrato](../WORKSPACE_API_v0.6.26.md).
