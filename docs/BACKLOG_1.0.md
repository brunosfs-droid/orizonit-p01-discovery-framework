# Cancã — backlog rastreável 1.0

Rebaseline 06/10/2026; execução atualizada em 07/10/2026 (-03).
R01 iniciou com [v0.6.21 CANDIDATE](WORKSPACE_FOUNDATION_v0.6.21.md): registry,
sites/ambientes/grants SQL/RLS/mapping. Backfill completo de inventário ainda pendente;
R01 completo e demais requisitos não são marcados como concluídos.
R02 iniciou com [v0.6.22](WORKSPACE_COORDINATOR_v0.6.22.md): lease por instalação,
generation/drain/jobs/cache limitados. Serviço/API workspace integrados nas
v0.6.25/26; Web/loader e adapters dos jobs legados ainda pendentes.
[v0.6.25](WORKSPACE_MODEL_v0.6.25.md) inicia R03–R05 com backend de histórico,
objetos/relações manuais e reconciliação identity. Serviço registra jobs e cerca
commits; backfill/UI e cobertura adicional mantêm os requisitos parciais.
[v0.6.26](WORKSPACE_API_v0.6.26.md) entrega listener humano separado para os
contratos backend, com binding/grants SQL; R06 segue parcial por migração,
recovery operacional, audit workspace e readers/reports legados. Recovery isolado
e lease por banco foram qualificados em [v0.6.27](WORKSPACE_RECOVERY_v0.6.27.md).
P0: fundação/isolamento; P1: experiência central; P2: profundidade incremental.
P2 pertence ao alvo 1.0; não significa exclusão automática. [Testes](TEST_PLAN_1.0.md).

| ID | Entrega | Prioridade | Fase | Dependência | Aceite |
|---|---|---|---|---|---|
| R01 | Workspace isolado, sites internos/ambientes opcionais | P0 | v0.6.x | Baseline | T01/T02; SQL/API/store não cruzam base. |
| R02 | Uma base aberta; lease/caches/jobs | P0 | v0.6.x | R01 | T03/T14; troca/crash sem contexto cruzado. |
| R03 | CollectionRun/observações/identidade histórica | P0 | v0.6.x | R01 | T04/T05; bytes/IDs/replay/idade preservados. |
| R04 | Relações/componentes/interfaces/redes/VLANs | P0 | v0.6.x | R03 | T02/T06; ownership/namespaces/ciclos. |
| R05 | Preview/diff/merge/evidência-only/categories | P0 | v0.6.x | R03/R04 | T05/T07; partial/drift/crash sem overwrite. |
| R06 | Migração/grants/fechamento Alpha | P0 | v0.6.x | R01–R05 | T01/T04/T13; regressão/recovery. |
| R07 | UI workspace/páginas de objetos | P1 | v0.7 | R06 | T08; administração separada de Visão geral. |
| R08 | Mapper/zoom/camadas/submapas | P1 | v0.7 | R04/R07 | T06/T08/T14; subgrafos e layouts. |
| R09 | Passivos/SFP/fibra/manual/ícones exportáveis | P1 | v0.7 | R04/R08 | T06/T12; declared/licença/arquivos restritos. |
| R10 | Rede: portas/VLAN/MAC/LLDP/CDP/regras | P1 | v0.8 | R04/R05 | T09; cobertura/contraprovas por vendor. |
| R11 | Inferência L2 downstream explicável | P2 | v0.8 | R10 | T09; AP/telefone/trunk não viram hub comprovado. |
| R12 | AD: privilégios/usuários/grupos/GPO/inatividade | P1 | v0.8 | R03/R05 | T10; timestamps/herança/cobertura. |
| R13 | Compute/capacidade/patch/EOL/Microsoft feed | P1 | v0.8 | R03/R16 | T10/T12; build/canal ou não avaliado. |
| R14 | VMware/Hyper-V/Proxmox; níveis KVM/Xen | P1 | v0.8 | R04/R05 | T11; host/VM/métricas sem duplicidade. |
| R15 | M365/Entra/licenças/AD/Graph | P1 | v0.8.x | R01/R12 | T10/T12; least privilege/identidade provada. |
| R16 | MIB/OID/feeds/firmware/drivers/Knowledge | P1 | v0.8 foundation / v0.8.x ampliação | R01/R03 | T12; offline/origem/validade/parsing. |
| R17 | Impressora/UPS/AP/telefone/câmera/storage/firewall | P2 | v0.8.x | R10/R16 | T09/T11/T12; perfil/versão qualificados. |
| R18 | Serviços/Desenho/impacto potencial | P1 | v0.7 base / v0.8 regras | R04/R08 | T06/T11; redundância/ciclos. |
| R19 | Dashboards/reports custom/ações/mudança | P1 | v0.9 | R10–R18 | T08/T15; snapshot/evidências/horizontes. |
| R20 | Backup servidor/workspace/restore/upgrade/GA | P0 segurança / P1 UX | v0.6 base / v0.9–1.0 | R01–R19 para GA | T13/T16; recovery isolado/matriz/zero blockers. |

## Primeiro lote

R01–R05 possuem fundamentos opt-in e fixtures adversariais A/B, com serviço/API
workspace qualificados. Próximas entregas: integração/backfill e readers/reports
por revisão, além de audit HTTP workspace. Mapper usa o grafo limitado após os
gates de fechamento Alpha. Recovery isolado T13 tem qualificação CI na v0.6.27;
R20 completo depende do restante somente para GA, evitando dependência circular.

O mantenedor autorizou iniciar desenvolvimento em 07/10/2026. Preparação concluída
na PR #132; implementação passa por qualificação própria e não encerra a Alpha.

## Recuperação v0.6.27

[Contrato](WORKSPACE_RECOVERY_v0.6.27.md): schema8 opt-in, lease vinculado ao banco,
reset de contexto/marker após restore e gate automático do par banco/store.
Qualificação em CI; não encerra migração/backfill, audit, restore cross-cluster ou
Alpha. R06/T13/R20 permanecem parciais. Nenhuma operação no LAB.

## Estado dos marcos após retomada das tarefas 1–4

[Registro de verificação](validation/WORKSPACE_TASK_RESUMPTION_2026-10-07.md).
O lote backend23–25 está integrado na PR #135; tarefas1–2 preservadas e tarefa3
comprovada por serviço/jobs, isolamento e cancelamento. A tarefa4 sincroniza os
marcos após verificar a baseline v0.6.27 e seu CI.

| Requisito | Entrega integrada | Gate ainda aberto |
| --- | --- | --- |
| R01 | Registry/sites/ambientes/grants/RLS e API workspace | Ownership/backfill completo do legado e integração dos readers/store. |
| R02 | Lease/generation/drain, serviço/API e fence por banco | Adapters de jobs/scanners legados, UI e benchmarks T14. |
| R03 | Histórico, observações/declarações e identidade | Backfill e demais categorias observadas. |
| R04 | Objetos/relações manuais e grafo limitado | Adapters observados de interfaces/redes/componentes e serviços. |
| R05 | Preview/apply identity, revisão e recibos | Reconciliação das demais categorias e fluxo completo de import. |
| R06 | API autenticada e recovery isolado PG16/17 | Migração completa, readers/reports, audit e qualificação operacional. |

Nenhum R01–R06 é declarado integralmente concluído. T13/R20 continuam parciais:
restore same-cluster/roles existentes não qualifica recuperação cross-cluster.
