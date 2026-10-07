# Cancã — implementação e migração para 1.0

Revisão 06/10/2026 (-03). Plano pronto para execução; nenhum schema/API/SQL novo
implantado nesta revisão. [Backlog](BACKLOG_1.0.md) · [Gates](TEST_PLAN_1.0.md).

## Extensão Alpha

| Incremento alvo | Entrega | Dependência | Saída verificável |
|---|---|---|---|
| v0.6.21 | Workspaces, sites/ambientes, ownership, grants e contratos | Baseline | Rejeição cross-workspace antes do acesso. |
| v0.6.22 | Lease de carga única, close/open, generation/caches/jobs | v0.6.21 | Multiaba/process-exit/troca sem contexto cruzado. |
| v0.6.23 | CollectionRun, Observation, Declaration e AssetIdentity | v0.6.21/22 | Histórico/replay/migração sem merge indevido. |
| v0.6.24 | Relationship, interfaces/componentes/rede/VLAN e serviços | v0.6.23 | Ownership, origens, ciclos e namespace de VLAN. |
| v0.6.25 | Prévia/diff, categories e commit/revisão | v0.6.23/24 | Idempotência, drift, partial e crash reconciliados. |
| v0.6.26+ | Migração completa, API foundations, regressão/fechamento | Todos | Recovery/grants/gates Alpha aprovados. |

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
serviços/findings/ações/reports. Não estão disponíveis hoje. Cada PR fixa schema,
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
