# P01 — Próximos passos da Product Alpha

Atualizado em 08/10/2026 (-03). Workspace HTTP Audit v0.6.29 CANDIDATE opt-in
sobre schema9; contratos legados v0.6.20/SNMP v0.4b.9 preservados.

## Próxima execução após replanejamento

[Especificação 1.0](PRODUCT_SPEC_1.0.md), [arquitetura](ARCHITECTURE.md),
[backlog](BACKLOG_1.0.md), [migração](IMPLEMENTATION_PLAN_1.0.md) e
[testes/EVE-NG](TEST_PLAN_1.0.md) passam a orientar o desenvolvimento.
Primeiro incremento implementado: [v0.6.21 CANDIDATE](WORKSPACE_FOUNDATION_v0.6.21.md),
registry Workspace/Site/Environment, grants SQL/RLS e mapping administrativo.
Opt-in em base isolada; não é migração completa de inventário nem upgrade da Web.
Fonte qualificada: 15 runs PASS, incluindo 18 casos sem skips por PostgreSQL 16/17
no workflow dedicado. [Evidência e limites](validation/WORKSPACE_FOUNDATION_CI_v0.6.21.md).
Segundo incremento: [v0.6.22 CANDIDATE](WORKSPACE_COORDINATOR_v0.6.22.md),
coordenador lógico de carga única/lease/generation/drain/cache. Fonte qualificada:
15 runs PASS, 44 casos
sem skips por PG16/17 e 687 casos locais/163 skips esperados.
[Evidência e limites](validation/WORKSPACE_COORDINATOR_CI_v0.6.22.md).
[v0.6.25](WORKSPACE_MODEL_v0.6.25.md), PR #135, já implementou o backend23–25:
observações/identidade, histórico, grafo manual e prévia/aplicação por revisão.
Preparo de import, leituras e escritas estão registrados no coordenador, com
cancelamento, isolamento A/B e rejeição de respostas antigas/revogadas.
[v0.6.26](WORKSPACE_API_v0.6.26.md), PR #136, entregou a API humana separada.
[v0.6.27](WORKSPACE_RECOVERY_v0.6.27.md), PR #137, entregou o fence por banco e
qualificou recuperação isolada. `main`3874be4: oito workflows/21 jobs PASS;
118 casos workspace sem skips e restore PASS por PG16/17.
[Retomada das tarefas 1–4 e evidência](validation/WORKSPACE_TASK_RESUMPTION_2026-10-07.md).

[v0.6.28](WORKSPACE_LEGACY_v0.6.28.md) acrescenta a ponte revisada do legado:
mapping explícito, verificação dos bytes, preview/apply identity transacional e
relatórios históricos por bundle/revisão. As avaliações/IDs antigos são conservados;
não executar findings correntes nem tratar ausência de análise como resultado limpo.
[Fonte qualificada](validation/WORKSPACE_LEGACY_CI_v0.6.28.md):15 runs/41 jobs,
141 casos sem skips e restores schema8/9 PASS por PG16/17.

[v0.6.29](WORKSPACE_AUDIT_v0.6.29.md) acrescenta auditoria HTTP workspace própria:
login/lifecycle/leitura/mutações/import/backfill/report recebem rótulos fixos; somente
IDs já confiáveis podem ser gravados e falha de admissão bloqueia trabalho antes do
backend. [Fonte qualificada](validation/WORKSPACE_AUDIT_CI_v0.6.29.md): 9 casos
audit PASS por PG16/17, regressão geral 793 PASS/217 skips esperados e restores
schema8/9 preservados.

## v0.6.30 — desenvolvimento em PR #141 (não integrado)

Leitor de categorias de inventário por tipo declarado, filtros de site/ambiente/kind/origin,
paginação por revisão, acesso HTTP autenticado e testes adversariais novos. Código
em branch de trabalho, pendente de resultado dos workflows no último HEAD; o CI
anterior da PR estava aprovado. **Não** qualifica readers observados de scanner,
migração completa ou recuperação operacional.

## v0.6.31 — cobertura delimitada de objetos registrados

A v0.6.31 candidata acrescenta resumo read-only por categoria/origem/tipo,
com escopo de páginas e continuidade explícitos; não é aferição de cobertura de
coleta, e não abre suporte a novo vendor nem completa migração.

## Próximos gates independentes

1. Ampliar migração/categorias/readers conforme os contratos e recovery operacional do
   conjunto banco/store/configuração/roles. Restore CI same-cluster já aprovado
   não comprova recuperação cross-cluster ou do LAB. O schema9 adiciona gate
   independente para cópias históricas, relatório e recibos restaurados.
2. Fechar R01–R06 somente após os gates correspondentes. UI/Mapper v0.7 usa os
   contratos HTTP qualificados; adapters dos jobs/scanners legados e categorias
   observadas adicionais continuam explicitamente pendentes.

A Alpha permanece aberta. As tarefas 1–3 deste lote já estão integradas; a tarefa4
reconcilia qualificação/integração/marcos sem repetir essas implementações.

Nenhum teste dependente do mantenedor é solicitado agora. Gates antigos abaixo
mantêm seus limites; testes novos serão propostos sobre a versão qualificada.

## Histórico de entregas e gates preservados

## Preciso testar alguma coisa agora?

v0.4b.9 conclui o incremento de [evidência SNMP e portable gerenciado](SNMP_EVIDENCE_PORTABLE_v0.4b.9.md):
o reader puro valida envelopes/coverage, o Asset Resolver preserva claims e proveniência
por OID/SHA, o Evidence Bundle valida o contrato e o importer compara o replay
server-side com o resultado embarcado. O portable v0.5e.7 recebe requests explícitos,
congela hashes, exige `--enable-snmp` em prévia/AUTH/FULL e retoma etapas concluídas
sem repetir rede. FULL parcial com acesso confirmado conserva cobertura em vez de
inventar campos ausentes. Collector continua sem login Cancã e o scheduler não
habilita SNMP automaticamente.

A fonte v0.4b.9 foi qualificada em 14 runs / 38 jobs / 198 etapas críticas; os
12 jobs SNMP executaram 88 casos cada (26 adapter + 28 planejamento/execução +
34 integração), sem skips. A regressão geral registrou 643 casos / 140 skips
esperados e PostgreSQL 16/17 preservou 188 casos sem skips por job. Vendors,
views/NAT reais, ACL NTFS e operação em equipamentos reais continuam CANDIDATE
e permanecem um gate separado. [Registro e limites](validation/SNMP_EVIDENCE_PORTABLE_CI_v0.4b.9.md).

As versões v0.4b.7 e v0.4b.8 permanecem como contratos anteriores qualificados,
mas a antiga pendência de integração resolver/bundle/importer/portable foi fechada
pela v0.4b.9. O próximo trilho SNMP planejado é v0.4b.10+ (adapters/integrações
adicionais); ele não exige repetir os testes sintéticos já aceitos da v0.4b.9.

**Não há validação solicitada hoje.** O mantenedor adiou os testes de LAB em
03/10. O download Web v0.6.13 e os incrementos Product Alpha posteriores
permanecem CANDIDATE quando não possuem aceite operacional específico; nenhum
R1 já aprovado deve ser repetido.

v0.6.13 acrescenta download completo de relatório pela Web: ZIP em memória com
JSON/Markdown, manifesto/SHA256 e cerca ligada ao relatório exibido. Mantém
somente SELECT e sessões/grants; não altera collector, store ou banco.
[Guia e limites](OPERATOR_WEB_EXPORT_v0.6.13.md). O novo gate de LAB será somente
baixar/verificar o arquivo e encerrar o servidor temporário; o roteiro ficará
fixado na revisão qualificada em CI. [Novo gate R1](LAB_OPERATOR_WEB_EXPORT_R1_v0.6.13.md):
pacote isolado, uma consulta/download, FILE PASS e STOP PASS. Oito runs/16 jobs
passaram no código 9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871;
[qualificação e limites](validation/OPERATOR_WEB_EXPORT_CI_v0.6.13.md).
Mapa/topologia passam a integrar a 1.0 conforme ADR 0036; não estão implementados neste incremento histórico.
