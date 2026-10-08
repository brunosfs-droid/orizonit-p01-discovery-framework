# Cancã — estado da revisão 1.0

Decisão: 06/10/2026 America/Sao_Paulo; verificação técnica 07/10 UTC.

Este registro preserva a revisão original. Para o estado posterior à integração
das PRs #133–137 e retomada das tarefas1–4, consultar o
[registro atualizado](validation/WORKSPACE_TASK_RESUMPTION_2026-10-07.md) e os
[próximos passos](NEXT_STEPS_v0.6.0.md).

## Estado anterior confirmado

- Repo público brunosfs-droid/orizonit-p01-discovery-framework, main.
- HEAD remoto/clone: `546d939ea50299ab3506dfb0d4546e6ddba0b714`.
- Último commit: docs: sync SNMP v0.4b.9 completion and next steps (#131).
- Working tree limpo antes da revisão; nenhuma PR aberta; #131 integrada.
- Sete workflows principais desse HEAD SUCCESS: Python CI, PostgreSQL CI,
  Operator Web CI, Operator Accounts CI, Optional Agent CI, Read-only SNMP CI,
  CodeQL. Jobs de atualização Dependabot também passaram.
- Baseline **v0.6.20 CANDIDATE**, SNMP **v0.4b.9 CANDIDATE**.
  CI não encerra Alpha nem qualifica todos os vendors/produção.

## Revisão preparada

Especificação workspace-first: sites internos/isolation/carga única/Mapper central/
administração separada. MVP/governança/edições, arquitetura, roadmap, backlog,
migração, testes/EVE-NG alinhados. Planejamento sem alteração executável,
migração implantada, quota, Graph, release/tag ou homologação LAB.
Versão permanece v0.6.20; Alpha aberta até qualificar novos fundamentos.

Primeiro incremento: R01/v0.6.21 alvo, contratos Workspace/Site/Environment,
ownership/grants/migração aditiva e testes A/B; depois carga única/histórico.
Mantenedor solicitou preparação e aviso antes de começar essa execução.

GitHub mantém documentação viva. OneDrive recebe snapshot formal com manifest/
hashes/referência da branch/commit, sem fonte editável concorrente.
