# Workspace Recovery v0.6.27 — qualificação CI

Data: 07/10/2026. **CANDIDATE opt-in schema8**. [PR #137](https://github.com/brunosfs-droid/canca/pull/137).

Fonte: `2cf1040ef3cdcbb16c661b8bb298ca034a9c1074`; tree `55275034feb69b9a941abe16feb948b5427aeab3`. Base: `cfad00138532ac2e7dfa183bf17461b3cca4c9f3`. O próximo commit altera somente documentação.

## Evidência remota

O ambiente local ficou indisponível antes deste incremento; nenhum teste local é alegado. Python CI da fonte executou **761 casos / 562 executados / 199 skips opt-in**, PASS (job112788190069, run37620186724). Compilação e CodeQL, PASS. Migrações1–7 preservadas; testes verificam prefixo7 fixo, prefixo8 explícito e upgrade8 recusado durante coordenador ativo.

Workspace CI: **118 casos por PostgreSQL, sem skips**, PASS:18 foundation +27 coordinator +30 model +13 service +19 API +10 recovery +um guard. Cada job também executou dump/store/restore descartável, PASS.

| PostgreSQL | Job da PR | Testes e restore |
| --- | --- | --- |
| 16 (160015) | [112788202102](https://github.com/brunosfs-droid/canca/actions/runs/37620190280/job/112788202102) | 118 / zero skips / restore PASS |
| 17 (170011) | [112788202214](https://github.com/brunosfs-droid/canca/actions/runs/37620190280/job/112788202214) | 118 / zero skips / restore PASS |

Logs dos dois jobs da PR conferidos. Restore compara logicamente28 tabelas (runtime separado e last_txid normalizado), policies FORCE RLS, estado/grafo e recibos. Stores copiados têm inventário SHA igual; fonte revalidada e corrupção temporária do receipt recusada. Prepare restaura closed/generation e limpa XIDs; token antigo e contexto de outra base são recusados, replay preserva conteúdo e a primeira nova declaração incrementa revision3→4. Dump preserva ACLs de roles sintéticas já existentes, incluindo execução privada negada do fence. Guard confere ambiente/container/cluster antes de fixture/DDL; destino template0 novo, removido ao final.

Teste adversarial independente mantém advisory lease real no banco postgres e clona seus PID/contexto no runtime de canca_workspace_ci. Schema8 recusa esse contexto: lock de outro banco não autentica o modelo atual. Outros casos: nonadmin/stale/live coordinator negados, conteúdo/revisão preservados pelo reset e upgrade/replay8 sem tocar legado.

## Runs da fonte

15 runs concluídos com success:

| Workflow | pull_request | push |
| --- | --- | --- |
| Workspace Foundation CI | [37620190280](https://github.com/brunosfs-droid/canca/actions/runs/37620190280) | [37620186638](https://github.com/brunosfs-droid/canca/actions/runs/37620186638) |
| Python CI | [37620190246](https://github.com/brunosfs-droid/canca/actions/runs/37620190246) | [37620186724](https://github.com/brunosfs-droid/canca/actions/runs/37620186724) |
| CodeQL | [37620190223](https://github.com/brunosfs-droid/canca/actions/runs/37620190223) | — |
| Read-only SNMP CI | [37620190271](https://github.com/brunosfs-droid/canca/actions/runs/37620190271) | [37620186631](https://github.com/brunosfs-droid/canca/actions/runs/37620186631) |
| Operator Accounts CI | [37620190225](https://github.com/brunosfs-droid/canca/actions/runs/37620190225) | [37620186652](https://github.com/brunosfs-droid/canca/actions/runs/37620186652) |
| Operator Web CI | [37620190266](https://github.com/brunosfs-droid/canca/actions/runs/37620190266) | [37620186635](https://github.com/brunosfs-droid/canca/actions/runs/37620186635) |
| PostgreSQL CI | [37620190276](https://github.com/brunosfs-droid/canca/actions/runs/37620190276) | [37620186630](https://github.com/brunosfs-droid/canca/actions/runs/37620186630) |
| Optional Agent CI | [37620190245](https://github.com/brunosfs-droid/canca/actions/runs/37620190245) | [37620186649](https://github.com/brunosfs-droid/canca/actions/runs/37620186649) |

## Limites

É recuperação lógica pequena/quiescente, mesmo cluster/major e roles existentes. Não qualifica roles/segredos/certificados/configuração em outro cluster, backup concorrente/operacional/agendado, PITR, HA ou RPO/RTO. Tempos do fixture não são benchmark. Nenhuma evidência/dump foi retida; hashes e flags agregados ficam nos logs, sem credencial/linhas privadas. Backfill, audit HTTP, reports/jobs legados, UI/Mapper, Windows nativo e LAB/EVE-NG seguem pendentes. R06/T13/R20 permanecem parciais. Nenhuma mudança no LAB ou ação do mantenedor solicitada.
[Contrato](../WORKSPACE_RECOVERY_v0.6.27.md).
