# P01 — Próximos passos da Product Alpha

Atualizado em 07/10/2026 (-03). Workspace Coordinator v0.6.22 CANDIDATE opt-in;
contratos legados v0.6.20/SNMP v0.4b.9 preservados.

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
coordenador lógico de carga única/lease/generation/drain/cache. R02 parcial até
integração Web/API/loader/jobs legados. Próximo: v0.6.23 observações/identidades,
depois relações e reconciliação.
Só então fechar Alpha e iniciar UI/Mapper v0.7. A Alpha permanece aberta.

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
