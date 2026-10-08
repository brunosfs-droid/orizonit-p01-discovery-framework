# Cancã — implementação e migração para 1.0

Plano 06/10/2026; execução atualizada em 08/10/2026 (-03).
[v0.6.21](WORKSPACE_FOUNDATION_v0.6.21.md) implementa registry/sites/ambientes/grants
e mapping opt-in; [v0.6.22](WORKSPACE_COORDINATOR_v0.6.22.md) acrescenta
coordenador lógico/lease/generation/drain/cache. Backfill/readers/jobs legados ainda
não integrados; R01/R02 permanecem parciais.
[v0.6.25](WORKSPACE_MODEL_v0.6.25.md) entrega o backend aditivo dos alvos23–25:
histórico/identidade, grafo manual, preview/apply e fence de commit. R03–R05
seguem parciais: categoria identity, sem backfill/observed adapters completos.
[v0.6.26](WORKSPACE_API_v0.6.26.md) integra o listener humano workspace;
[v0.6.27](WORKSPACE_RECOVERY_v0.6.27.md) qualifica lease por banco e restore isolado.
[v0.6.28](WORKSPACE_LEGACY_v0.6.28.md) adiciona a ponte revisada de identidade do
legado e relatórios históricos por bundle/revisão; migração completa ainda pendente.
[v0.6.29](WORKSPACE_AUDIT_v0.6.29.md) qualifica auditoria HTTP workspace privada,
fail-closed e redigida, sem alteração de schema.
[Estado das tarefas e CI](validation/WORKSPACE_TASK_RESUMPTION_2026-10-07.md).
[Backlog](BACKLOG_1.0.md) · [Gates](TEST_PLAN_1.0.md).

## Extensão Alpha

| Incremento alvo | Entrega | Dependência | Saída verificável |
|---|---|---|---|
| v0.6.21 | Workspaces, sites/ambientes, ownership, grants e contratos | Baseline | Rejeição cross-workspace antes do acesso. |
| v0.6.22 | Lease de carga única, close/open, generation/caches/jobs | v0.6.21 | Multiaba/process-exit/troca sem contexto cruzado. |
| v0.6.23 | CollectionRun, Observation, Declaration e AssetIdentity | v0.6.21/22 | Histórico/replay/migração sem merge indevido. |
| v0.6.24 | Relationship, interfaces/componentes/rede/VLAN e serviços | v0.6.23 | Ownership, origens, ciclos e namespace de VLAN. |
| v0.6.25 | Prévia/diff, categories e commit/revisão | v0.6.23/24 | Idempotência, drift, partial e crash reconciliados. |
| v0.6.26 | API humana workspace, bindings SQL e limites | Backend23–25 | Integrada/CI qualificado; migração completa e audit continuam pendentes. |
| v0.6.27 | Lease por banco e recovery isolado schema8 | v0.6.26 | Integrada/118 casos e restore PASS por PG16/17; recovery operacional pendente. |
| v0.6.28 | Backfill identity revisado e relatórios históricos schema9 | v0.6.27 | Bytes/IDs/avaliações preservados, atomicidade/drift/replay e restore schema9 qualificados. |
| v0.6.29 | Auditoria HTTP workspace privada e redigida | v0.6.28 | Admissão fail-closed, IDs confiáveis e nenhuma cópia de secrets/body/query; PG16/17. |
| Próximos v0.6.x | Migração/readers adicionais e fechamento | v0.6.21–29 | Migração/recovery/gates Alpha aprovados no escopo correspondente. |

Versões são alvos, não releases publicadas. Mais patches podem ser necessários.
Não refazer v0.6.13–20 ou SNMP v0.4b.9 já implementados.

## Áreas de desenvolvimento

| Área atual | Evolução planejada |
|---|---|
| persistence/migrations | Aditivas após 0004: workspaces/ownership/grants, observações/projeções e grafo; checksum/recovery preservados. |
| P01_PostgreSQL / Ingestion_Index | Contexto por workspace, transação/RLS/roles e binding de imports. |
| Assessment_Lifecycle / Asset_Registry | Mapping legado, identidade por base entre runs, histórico/reconciliação. |
| Findings / Assessment_Report / Executive_Report | Actions e readers por snapshot/revisão/cobertura; compatibility pinada. |
| server/P01_Operator_* | Grants/rotas por base, coordenação de carga/cancelamento/downloads/cache. |
| server/web | Navegação servidor/workspace, wizard, páginas de objeto, Mapper/submapas e declarações. |
| ingestion / evidence_bundle | Envelope externo para destino legado, seleções versionadas, preview/apply/recovery. |
| asset_resolver / schemas | Sinais/IDs qualificados, relações/origem e compatibilidade versionada. |
| runtime / orchestrator / connected | Intenção de destino/scopes vinculados; scanner sem login para coletar. |
| collectors / credentialed_enrichment | Portas/VLAN/MAC/LLDP e adapters virtualização/Graph nas fases seguintes. |
| tests / workflows | Suites adversariais/migração/recovery PG16/17, browser/Mapper e benchmarks. |

Módulos novos: coordenador de Workspace, Reconciliação, reader de Grafo,
Catálogos/Knowledge e Action Planning. Nomes fixados nas PRs conforme convenções.

## Migração

1. Capturar checksums/dump/store/grants/contagens e verificar restore em fixture.
2. Adicionar ownership de modo aditivo. Mapping assessment → workspace escolhido
   explicitamente pelo operador, nunca por CIDR/nome/realm/workspace aberto.
3. Preservar IDs/hashes de bundles e legacy assets. Mapping de origem; cruzar
   assessments da mesma base somente com regras qualificadas/decisão manual.
   Node físico compartilhado mantém autorizações independentes por base.
4. Backfill em lotes transacionais/fenced; conferir órfãos/contagens/hashes/replay.
   Pendências em review_required, sem associação automática.
5. Chaves compostas/RLS/grants: permissão de assessment não vira admin ou grant
   para toda a base; manter acesso exato. Migrator/owners separados de reader/writer.
6. Paths particionados ou mapping read-only do legado. Bytes/origem intactos;
   cópia só com manifest/hash/publicação atômica e sem symlinks/traversal.
7. Readers/endpoints opt-in após qualificação. Legacy exige mapping autorizado;
   request sem workspace não utiliza automaticamente a base aberta.
8. Regressão dos snapshots antigos, replay offline/mTLS/contas/backup/restore;
   registrar commit/versão/limites antes de promover.

Rollback operacional restaura par banco/store/configuração anterior verificado.
Não prometer down-migration destrutiva após escritas novas; preservar novas fontes
fora do snapshot anterior para reaplicação revisada.

## APIs e recursos

Rotas conceituais de administração listam/criam bases e solicitam open/close;
`/workspaces/{id}/...` serve sites/objetos/grafo/import preview/apply/declarações/
serviços/findings/ações/reports. A API v0.6.26 implementa inventário/grafo/declarações
e imports; v0.6.28 acrescenta backfill e relatório histórico por bundle. Demais
rotas conceituais continuam planejadas. Cada PR fixa schema,
grants, tamanho/deadline, erros, idempotência e revision fence antes de codificar.
Mutações exigem revisão esperada/autorização/auditoria redigida. Upload MIB/ícone
usa parser restrito, sem executar plugin ou comando arbitrário.

Estimar por gates. Ordens da conversa (Alpha 3–5 semanas, UI 6–10, inteligência
10–16, extensões 5–8, RC 6–10, GA 4–6) são hipóteses, não compromisso de prazo
ou autonomia em background. Reestimar após migração/isolamento e primeiro vendor.
LAB, permissões Graph/catálogos e validação humana são dependências reais.

Benchmark alvo: 100/1.000/10.000 objetos; visão agregada sem inventário completo;
submapa inicial até 500 nós/2.000 arestas e páginas default de teste de 100 objetos.
Registrar hardware, p50/p95, RAM/cancelamento/concorrência e 20 trocas. Orçamento
final de latência/RAM depende da medição, não é capacidade comercial garantida.

## Sequência executável após o backend23–25

1. [v0.6.26](WORKSPACE_API_v0.6.26.md): API humana opt-in implementada, com
   binding operador/role SQL explícito, workspace/generation, limites/erros e
   revalidação de sessão/grant. Não encerra integração/migração/audit de R06.
2. [v0.6.27](WORKSPACE_RECOVERY_v0.6.27.md): recovery isolado schema8 e fence por
   banco integrados/qualificados; contrato anterior permanece pinado em8.
3. [v0.6.28](WORKSPACE_LEGACY_v0.6.28.md): ponte revisada de identidade e relatório
   histórico de avaliações existentes por bundle/revisão; contratos v0.6.26/schema7
   e v0.6.27/schema8 preservados, listener atual exige9.
4. [v0.6.29](WORKSPACE_AUDIT_v0.6.29.md): auditoria HTTP workspace própria,
   opt-in, fail-closed e redigida, qualificada em PG16/17. Próximos gates:
   migração/readers adicionais e recovery operacional; fechar R06 somente após eles.
5. v0.7: seleção/abertura/fechamento, páginas de objetos e Mapper limitado; Visão
   geral da base separada da Administração do servidor, sites internos.
6. Adapters observados adicionais e fixtures EVE-NG versionadas, seguidos dos
   gates de vendor/cobertura antes de alegar suporte de coleta real.

Autorização do mantenedor: continuar os desenvolvimentos sem consultas rotineiras.
Dependências externas são registradas e não impedem desenvolvimento sintético.

## Recuperação v0.6.27

[Contrato](WORKSPACE_RECOVERY_v0.6.27.md): schema8 opt-in, lease vinculado ao banco,
reset de contexto/marker após restore e gate automático do par banco/store.
Qualificação em CI; não encerra migração/backfill, audit, restore cross-cluster ou
Alpha. R06/T13/R20 permanecem parciais. Nenhuma operação no LAB.
