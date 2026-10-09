# Cancã — backlog rastreável 1.0

[v0.6.65 — integridade com regrant](WORKSPACE_LEDGER_REGRANT_INTEGRITY_v0.6.65.md): decisões persistidas não mudam após revogação/reconcessão; v0.6.64 integrada pelo PR #175; E0 pendente.

[v0.6.64 — decisões imutáveis na revogação](WORKSPACE_LEDGER_REVOCATION_IMMUTABILITY_v0.6.64.md): revogação de leitor não altera decisão histórica; v0.6.63 integrada pelo PR #174; E0 pendente.

[v0.6.63 — regrant seletivo A/B](WORKSPACE_LEDGER_SELECTIVE_REGRANT_v0.6.63.md): revogação e nova concessão em B não revelam intenção de A; v0.6.62 integrada no PR #173; E0 pendente.

[v0.6.62 — revogação seletiva A/B](WORKSPACE_LEDGER_SELECTIVE_REVOCATION_v0.6.62.md): revogar leitura em B preserva a leitura legítima em A; v0.6.61 integrada pelo PR #172; E0 pendente.

[v0.6.61 — grants adicionais sem vazamento](WORKSPACE_LEDGER_GRANT_EXPANSION_v0.6.61.md): ampliação explícita de leitura A/B não expõe histórico fora do workspace; v0.6.60 integrada pelo PR #171; E0 pendente.

[v0.6.60 — grants isolados por workspace](WORKSPACE_LEDGER_CROSS_GRANT_v0.6.60.md): acesso concedido em A não autoriza B; v0.6.59 integrada no PR #170; E0 pendente.

[v0.6.59 — token obsoleto e histórico SQL](WORKSPACE_LEDGER_STALE_TOKEN_HISTORY_v0.6.59.md): token de geração antiga não pode consultar ledger após troca de workspace; v0.6.58 integrada pelo PR #169; E0 pendente.

[v0.6.58 — histórico sob troca A–B–A](WORKSPACE_LEDGER_SWITCHBACK_v0.6.58.md): decisões antigas preservadas como evidência sem autorização na nova lease; v0.6.57 integrada pelo PR #168; E0 pendente.

[v0.6.57 — isolamento de leitura A/B](WORKSPACE_LEDGER_CROSS_READER_v0.6.57.md): intenção aprovada em A permanece invisível em B; v0.6.56 integrada no PR #167; E0 pendente.

[v0.6.56 — regrant continua somente leitura](WORKSPACE_LEDGER_REGRANT_READONLY_v0.6.56.md): reader não altera decisões após nova concessão de leitura; v0.6.55 integrada pelo PR #166; E0 pendente.

[v0.6.55 — regrant de leitor do ledger](WORKSPACE_LEDGER_READER_REGRANT_v0.6.55.md): acesso histórico recuperado somente com regrant SQL; v0.6.54 integrada pelo PR #165; E0 pendente.

[v0.6.54 — revogação SQL do histórico](WORKSPACE_LEDGER_READER_REVOCATION_v0.6.54.md): leitor revogado é bloqueado, outro leitor mantém acesso; v0.6.53 integrada no PR #164; E0 pendente.

[v0.6.53 — auditoria de negações HTTP](WORKSPACE_LEDGER_HTTP_AUDIT_DENIALS_v0.6.53.md): proteger logs de requisições com parâmetros indevidos e sessões revogadas; v0.6.52 integrada no PR #163; E0 pendente.

[v0.6.52 — auditoria HTTP sem vazamentos](WORKSPACE_LEDGER_HTTP_AUDIT_REDACTION_v0.6.52.md): teste de não exposição de intenção, rota ou parâmetros da query; v0.6.51 integrada no PR #162; E0 pendente.

[v0.6.51 — admissão HTTP auditada](WORKSPACE_LEDGER_AUDIT_ADMISSION_v0.6.51.md): negação fail-closed antes do backend e recuperação após restabelecimento do sink; v0.6.50 integrada pelo PR #161, E0 pendente.

[v0.6.50 — gate negativo HTTP](WORKSPACE_LEDGER_HTTP_NEGATIVE_v0.6.50.md): proteger histórico de ledger contra query duplicada, credenciais em parâmetro, sessão encerrada e identificadores inválidos; v0.6.49 integrada no PR #160; E0 pendente.


[v0.6.49 — regressão HTTP](WORKSPACE_HTTP_ROUTE_REGRESSION_v0.6.49.md): proteção dos captures de legacy/report/readiness e do histórico do ledger; nenhuma execução ou autorização. v0.6.48 integrada pelo PR #159; E0 pendente.

[v0.6.48 — histórico HTTP do ledger](WORKSPACE_LEDGER_HISTORY_HTTP_v0.6.48.md): candidato R02/R06; consulta autenticada e auditada do histórico, sem aprovação ou execução via HTTP. v0.6.47 integrada no PR #158; EVE-NG e Product Alpha não homologados.

[v0.6.47 — concorrência do ledger](WORKSPACE_LEDGER_CONCURRENCY_v0.6.47.md): candidata R02/R06; três corridas reais de decisões, transições terminais e replay idempotente em PG16/17. Apenas histórico, sem executar scanner. v0.6.46 integrada via PR #157; E0/cross-cluster ainda não homologados.

[v0.6.45 — ledger transacional](WORKSPACE_INTENT_LEDGER_v0.6.45.md): candidato R02/R06, schema10 opcional, decisões append-only com TTL/lease/geração e autoria SQL. Não habilita execução. v0.6.44 integrada via PR #155; leitura estrutural de audit qualificada.

[v0.6.43 — HTTP audited scan preview](WORKSPACE_AUDITED_SCAN_PREVIEW_v0.6.43.md) — candidato R02: endpoint somente-prévia com grant write e trilha de auditoria obrigatória, sem CIDRs/credenciais/client targets. Não autoriza AUTH/FULL nem fecha R02/EVE-NG.

[v0.6.42 — Intent review receipts](WORKSPACE_INTENT_RECEIPTS_v0.6.42.md) — candidato R02 empilhado sobre v0.6.41: comprovante efêmero de revisão TTL/consumo único, ligado a escopo, lease e geração; nunca autoriza execução nem substitui ledger persistente/assinatura/LAB.

[v0.6.41 — Live scan intent preview](WORKSPACE_LIVE_INTENT_v0.6.41.md) — candidate R02: escopos IPv4 privados em política imutável, geração/lease, grant write e digest sem credenciais/targets; nenhuma execução AUTH/FULL ou varredura. Gates de segurança, EVE-NG e Alpha permanecem abertos.

[v0.6.40 — Process group fence](WORKSPACE_LEGACY_PROCESS_GROUP_v0.6.40.md) — candidato R02: encerramento de grupo de subprocessos locais POSIX no checkpoint somente-leitura, com testes de órfãos e de fechamento concorrente; Windows, scanners ativos, EVE-NG e R02 completo continuam pendentes.
[v0.6.39 — Legacy job fence](WORKSPACE_LEGACY_JOB_FENCE_v0.6.39.md) — integrado via PR #150: checkpoint read-only sob geração/lease/cancelamento do coordenador; ainda não habilita scanners ativos, encerramento de grupos ou R02 completo.
[v0.6.37 — E0/recovery preflight](LAB_ALPHA_E0_AND_RECOVERY_R1.md) — integrado via PR #148: roteiro e verificação offline, sem homologação operacional/restore cross-cluster.
[v0.6.38 — Legacy readiness](WORKSPACE_LEGACY_READINESS_v0.6.38.md): integrada via PR #149; leitura limitada por bundle histórico autorizado, com revalidação SQL→store e recibo imutável. CI e integração não encerram migração completa, outras categorias ou R01/R03. A homologação E0/recovery da PR #148 permanece gate operacional independente.

[Auditoria R01–R06 e critérios E0 (08/10)](validation/ALPHA_R01_R06_GATE_MATRIX_2026-10-08.md) · [Roteiro E0/recovery R1](LAB_ALPHA_E0_AND_RECOVERY_R1.md). São artefatos para qualificação, não aceite de LAB, fechamento Alpha ou release. O preflight offline verifica somente integridade dos artefatos, não executa restore.
[v0.6.36](WORKSPACE_CATEGORY_SIGNAL_COVERAGE_v0.6.36.md) — candidata: visão limitada de sinais efetivamente registrados por categoria e filtros, sem inferir cobertura de rede; CI/EVE-NG/Alpha separados.
[v0.6.35](WORKSPACE_OBSERVATION_COMPARISON_v0.6.35.md) — integrada via PR #146: comparação de dois lotes de recebimento por tipo de sinal com proveniência e sem inferência de drift; R03/R05 seguem parciais, EVE-NG/Product Alpha independentes.
[v0.6.34](WORKSPACE_SIGNAL_QUALITY_v0.6.34.md) — CI aprovado e PR #145 integrado à main; diagnósticos de conflito/proveniência, sem validar cobertura real.
[v0.6.33](WORKSPACE_SIGNAL_SUMMARY_v0.6.33.md) — integrada via PR #144: síntese limitada de sinais efetivamente observados por objeto, conflitos explícitos e proveniência (sem inferências, sem promoção de declarações). Gate de CI, integração e EVE-NG independentes; R03/R05/R06 ainda parciais.
[v0.6.32](WORKSPACE_OBSERVED_SIGNALS_v0.6.32.md) PR #143 integrado: leitor de observações persistidas com proveniência, sem promoção de declarações; EVE-NG e Product Alpha ainda pendentes. [Gates](validation/WORKSPACE_OBSERVED_SIGNALS_GATES_v0.6.32.md).

Rebaseline 06/10/2026; execução atualizada em 08/10/2026 (-03).
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
recovery operacional e readers adicionais. Recovery isolado
e lease por banco foram qualificados em [v0.6.27](WORKSPACE_RECOVERY_v0.6.27.md).
[v0.6.28](WORKSPACE_LEGACY_v0.6.28.md) adiciona backfill identity revisado e
relatórios históricos por bundle/revisão. O gate de migração completa permanece aberto.
[Qualificação v0.6.28](validation/WORKSPACE_LEGACY_CI_v0.6.28.md):141 casos sem
skips por PG16/17 e restores schema8/9, preservando tarefas1–3 e marcos anteriores.
[v0.6.29](WORKSPACE_AUDIT_v0.6.29.md) qualifica auditoria HTTP própria, privada e
fail-closed sem schema novo. [Evidência](validation/WORKSPACE_AUDIT_CI_v0.6.29.md):
9 casos audit por PG16/17 e regressão geral 793 PASS/217 skips esperados.
[v0.6.30](WORKSPACE_CATEGORY_READER_v0.6.30.md), PR #141 (rascunho), acrescenta
readers categorizados por tipo declarado, filtros explícitos, paginação e rota
HTTP; a qualificação no último commit está pendente. Não marcar R03–R06 fechados.
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
workspace qualificados, ponte revisada de legado/relatório por bundle na v0.6.28
e auditoria HTTP própria qualificada na v0.6.29.
Próximas entregas: migração/categorias/readers adicionais e recovery operacional.
Mapper usa o grafo limitado após os
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
| R01 | Registry/sites/ambientes/grants/RLS, API e ponte mapeada do legado | Ownership/backfill completo e demais readers/store. |
| R02 | Lease/generation/drain, serviço/API e fence por banco | Adapters de jobs/scanners legados, UI e benchmarks T14. |
| R03 | Histórico, observações/declarações, identidade e backfill revisado | Demais categorias observadas e migração completa. |
| R04 | Objetos/relações manuais e grafo limitado | Adapters observados de interfaces/redes/componentes e serviços. |
| R05 | Preview/apply identity e legado, revisão/recibos | Reconciliação das demais categorias e fluxo completo de import. |
| R06 | API autenticada, ponte/relatório histórico, audit HTTP e recovery isolado schema8/9 PG16/17 | Migração/readers completos e qualificação operacional. |

Nenhum R01–R06 é declarado integralmente concluído. T13/R20 continuam parciais:
restore same-cluster/roles existentes não qualifica recuperação cross-cluster.
