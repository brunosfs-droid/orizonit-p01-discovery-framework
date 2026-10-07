# Workspace Model v0.6.25 — qualificação CI

Data: 07/10/2026. **CANDIDATE opt-in**. [PR #135](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/135).

Fonte executável: `6a94c2ff44a43dd307966e9ee2473eff5b2b657d`; tree `a143c68d1b2dd7c0ff5e1303b6440517f0bb4e21`.
Base: `a61b494ac22481f3da953ef6cc70217237e4ae94`. O commit deste registro altera somente documentação.

## Evidência

Suíte local: **731 casos / 542 executados / 189 skips opt-in**, PASS. Compilação e diff check, PASS. SQL1–6 preservado; nenhuma evidência/linha legada reescrita. O erro backup_restore_failed impresso por um caso negativo é esperado; exit0 da suíte.

PostgreSQL16 e17: **88 casos por job, sem skips**, PASS. Cada job executou18 foundation +27 coordinator +30 model +13 service. Logs dos dois jobs da PR conferidos, inclusive rollback de conteúdo após pg_terminate_backend e source preview/apply registrado como job.

| PostgreSQL | Job da PR | Resultado |
| --- | --- | --- |
| 16 | [112773708174](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802770/job/112773708174) | 88 / zero skips / PASS |
| 17 | [112773707820](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802770/job/112773707820) | 88 / zero skips / PASS |

Cobertura nova: histórico imutável e autoria SQL, observado/declarado/retração, sinais qualificados/corroborados e conflito manual, evidência-only, idade por recebimento, planos sem incremento de revisão, replay/drift, aplicação atômica, namespace A/B com evidência/sinais iguais, FKs de site/objeto da base, RLS/grant revogado, grafo cíclico limitado/eventos de remoção, paginação por revisão, close durante commit, sessão perdida/rollback e migração7 impedida com coordenador vivo. Adapter: diretórios disjuntos, handles estritos, source tamper, job durante preparo, cancelamento/resposta tardia, grant revogado e geração/conexão antiga.

## Runs da fonte

15 runs (oito PR/sete push) concluídos com success:

| Workflow | pull_request | push |
| --- | --- | --- |
| Workspace Foundation CI | [37615802770](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802770) | [37615796715](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615796715) |
| Operator Web CI | [37615802774](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802774) | [37615796734](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615796734) |
| Operator Accounts CI | [37615802718](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802718) | [37615796700](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615796700) |
| CodeQL | [37615802830](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802830) | — |
| Read-only SNMP CI | [37615802793](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802793) | [37615796661](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615796661) |
| Python CI | [37615802729](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802729) | [37615796662](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615796662) |
| PostgreSQL CI | [37615802716](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802716) | [37615796688](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615796688) |
| Optional Agent CI | [37615802719](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615802719) | [37615796657](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37615796657) |

## Falha inicial e correção

Fonte inicial `5e941c591fcf658add9fb5edd310ed9eaf959925` não foi qualificada. PostgreSQL16/17 detectou que shutdown, ao descobrir a perda do lease pela primeira vez, levantava erro antes de concluir sua limpeza. O teste já comprovava rollback SQL, mas falhava na terminação do coordenador. A fonte acima conclui a limpeza também nesse caminho e adiciona caso determinístico; o teste real passa nas duas versões. Não houve rerun para ocultar falha de código.

## Limites

Backend dos alvos23–25; somente identity observado. Não qualifica migração/backfill completo, API humana, UI/Mapper, reports/jobs legados, restore7, Windows nativo, benchmarks ou equipamentos/EVE-NG. Serviços e relações são declarações, sem disponibilidade comprovada. Recebimento não prova horário de coleta. Cancelamento é cooperativo; commit concluído com resposta cancelada exige recibo/replay. DB maintenance/configuração e credenciais SQL internas são confiáveis. R03–R05/Alpha continuam parciais. Nenhum upgrade/scan no LAB e nenhuma ação do mantenedor foi solicitada.
[Contrato](../WORKSPACE_MODEL_v0.6.25.md).
