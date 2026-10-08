# Cancã — retomada verificada das tarefas 1–4

Solicitação e referência de data: 07/10/2026 America/Sao_Paulo (08/10 UTC).
Escopo: conferir repositório, commits/branches/alterações, PR/revisão e CI antes
de retomar a tarefa3 ou4, preservando as duas etapas já concluídas.

## Baseline verificada

- Repositório: [brunosfs-droid/orizonit-p01-discovery-framework](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework).
- Branch de integração: `main`, commit
  [3874be4d4e39bf485ba72c1fc1ff8e631a0fc0a1](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/commit/3874be4d4e39bf485ba72c1fc1ff8e631a0fc0a1),
  tree `a65244cf06c73b24f586cbbabb621c75ba271e50`.
- Último commit executável integrado: v0.6.27 database-bound workspace leases and
  isolated restore (#137), 07/10/2026 09:31:16 (-03).
- Cópia local mais recente encontrada: `feature/workspace-human-api`, `a311851`,
  working tree limpa, anterior ao head remoto. `git fetch origin main` confirmou
  a atualização; worktree isolada criada a partir do head remoto para esta revisão.
  Cópias/rascunhos anteriores não foram sobrescritos nem publicados.
- Nenhum PR aberto na auditoria. PRs #135–137 integradas; nenhum review humano
  submetido nessas três PRs. O estado merged e os checks foram conferidos
  diretamente; ausência de review humano não é apresentada como aprovação humana.
- Baseline workspace **v0.6.27 CANDIDATE opt-in schema8**; Alpha permanece aberta.
  Esta revisão altera somente Markdown, sem criar versão executável ou release.

## Decisão de retomada

| Tarefa | Estado comprovado | Evidência |
| --- | --- | --- |
| 1. Consolidar contratos de histórico, identidade e grafo por workspace | Concluída e preservada | [Contrato v0.6.25](../WORKSPACE_MODEL_v0.6.25.md), ADR0039 e PR #135. |
| 2. Implementar e testar observações, declarações e reconciliação transacional | Concluída e preservada | Modelo/schema7, testes model e [qualificação](WORKSPACE_MODEL_CI_v0.6.25.md), PR #135. |
| 3. Integrar operações ao coordenador e validar isolamento/cancelamento | Já concluída e integrada | WorkspaceService registra preparo/reads/writes; testes service/coordinator/model e PR #135. |
| 4. Qualificar no CI, integrar e atualizar próximos marcos | Backend já qualificado/integrado; marcos reconciliados nesta revisão | CI de main abaixo; README/CHANGELOG/roadmap/backlog/plano/next steps atualizados. |

Integrações existentes:

| PR | Commit em main | Entrega |
| --- | --- | --- |
| [#133](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/133) | `741f482` | Fundação workspace v0.6.21. |
| [#134](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/134) | `a61b494` | Coordenador v0.6.22. |
| [#135](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/135) | `3fcd4c7` | Backend23–25 e integração das operações ao coordenador. |
| [#136](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/136) | `cfad001` | Listener humano workspace v0.6.26. |
| [#137](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/137) | `3874be4` | Fence por banco/recuperação isolada v0.6.27. |

A sequência coordenador → isolamento/cancelamento → CI → integração foi
comprovada no código/testes e nas integrações existentes. Não se refaz tarefa3.
Fechamento durante preparo impede prévia tardia; tokens antigos e grants
revogados suprimem resultados. Commit já concluído reconcilia por recibo: uma
resposta suprimida não comprova rollback. Perda da sessão antes do commit causa
rollback, conforme o teste PostgreSQL dedicado.

## CI da baseline integrada3874be4

Oito runs de push e 21 jobs concluídos com success, conferidos por head_sha e
etapas. Skips condicionais de SCM/systemd por sistema operacional são esperados;
as etapas workspace/model/service/API/recovery foram executadas com success.

| Workflow | Run | Jobs | Resultado |
| --- | --- | --- | --- |
| Python CI | [37621587624](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587624) | 1 | PASS |
| Workspace Foundation CI | [37621587686](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587686) | 2 | PASS |
| PostgreSQL CI | [37621587791](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587791) | 2 | PASS |
| Operator Web CI | [37621587694](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587694) | 1 | PASS |
| Operator Accounts CI | [37621587746](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587746) | 4 | PASS |
| Optional Agent CI | [37621587792](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587792) | 4 | PASS |
| Read-only SNMP CI | [37621587543](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587543) | 6 | PASS |
| CodeQL | [37621587787](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587787) | 1 | PASS |

Logs relidos: Python job112792910132, **761 casos/562 executados/199 skips opt-in**,
PASS. Workspace jobs [PG16/112792910789](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587686/job/112792910789)
e [PG17/112792910553](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37621587686/job/112792910553),
**118 casos sem skips por job**: 18 foundation, 27 coordinator, 30 model, 13 service,
19 API, 10 recovery e um guard. Em cada job, WORKSPACE BACKUP RESTORE PASS,
28 tabelas comparadas, revisões/grafo/recibos/bytes/RLS e ACLs das roles existentes
preservados; contexto antigo e recibo corrompido recusados. Restore usa fixtures
descartáveis no mesmo cluster/major, sem qualificar recuperação cross-cluster.

## Atualização dos marcos

R01–R06 permanecem **parciais**, com entregas discriminadas no
[backlog](../BACKLOG_1.0.md). Próximos gates: backfill/import revisado do legado,
readers/findings/reports por revisão/cobertura, audit HTTP workspace e recovery
operacional de banco/store/configuração/roles. R02 ainda requer adapters de jobs/
scanners legados, UI e benchmark; R03–R05 requerem demais categorias observadas.
T13/R20 não estão encerrados pelo restore same-cluster. UI/Mapper v0.7 segue os
gates Alpha; aceites LAB anteriores permanecem válidos nos escopos registrados.

Validação desta revisão documental: links locais/fences e git diff --check.
Workflows e integração desta branch ficam rastreáveis na PR associada ao commit;
os resultados acima pertencem exclusivamente ao SHA3874be4, sem atribuir os
testes anteriores a um head ainda não executado. Nenhuma nova ação manual no LAB.
