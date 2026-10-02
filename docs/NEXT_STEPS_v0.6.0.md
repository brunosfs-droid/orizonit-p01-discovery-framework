# P01 — Próximos passos da Product Alpha

Atualizado em 02/10/2026 (-03), após v0.6.7 e resultados do soak estendido.

## Preciso testar alguma coisa agora?

**O desenvolvimento de código/CI segue independentemente do LAB PostgreSQL.** R1 curto e soak estendido
do scheduler estão aprovados em Windows e Rocky no escopo offline demonstrado.
Não é preciso repetir os testes ou reinstalar serviços removidos pelo helper.

O soak estendido usou 10 ticks com intervalo real de 60s, ciclos de 540,911s e
540,310s, auditorias PASS e exit 0 nos dois hosts. Intenções interrompidas e fixtures
ficam preservadas; o restart em revisão com zero chamadas é esperado.
[Aceite e limites](validation/SCHEDULER_P01LAB_EXTENDED_v0.5f.3.md).

Multi-day e qualificação do principal para AUTH/FULL/POST continuam independentes;
o soak offline de cerca de 9 minutos não os comprova. Não há execução live proposta
como dependência deste incremento.

## PostgreSQL e desenvolvimento

v0.6.0 entregou a fundação do índice; v0.6.1 integrou ingestão/índice de forma opt-in
e reconciliação explícita; v0.6.2 adiciona ciclo de vida administrativo do assessment
com revisão, idempotência e histórico transacional. v0.6.3 entrega identidade
persistente de assets por assessment, com origem verificável e revisão de
ambiguidades. v0.6.4 adiciona findings de duas regras WinRM com origem, cobertura explícita e
ocorrências imutáveis, sem fechar findings de runs anteriores. v0.6.5 consolida consultas de lifecycle, identidade, cobertura e ocorrências
históricas, com paginação consistente. v0.6.6 qualifica a recuperação de banco/store
em CI descartável, com comparação integral, hashes e replay. v0.6.7 adiciona um helper somente leitura para verificar a recuperação na fixture R1.
O R1 básico está **LAB VALIDATED** em PostgreSQL 16.15; recuperação operacional,
TLS/roles completos e restante da Product Alpha continuam CANDIDATE.

O roteiro R1 abaixo orienta a instalação em base/store isolados; não altere o store atual.
Nenhuma migração é automática. A recuperação sintética em CI está implementada;
o harness destrutivo de CI não deve ser executado no LAB. Recuperação operacional,
contas e TLS remoto requerem qualificação própria após o gate inicial. Resolução manual e
continuidade de IDs entre assessments terão decisões próprias.

[Findings v0.6.4](FINDINGS_v0.6.4.md) ·
[Assets v0.6.3](ASSET_REGISTRY_v0.6.3.md) ·
[Lifecycle v0.6.2](ASSESSMENT_LIFECYCLE_v0.6.2.md) ·
[Integração v0.6.1](INGESTION_INDEX_v0.6.1.md) ·
[R1 curto](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md)

## R1 PostgreSQL básico aprovado

As 18 capturas demonstram PostgreSQL 16.15 active/running em loopback, 64MB shared_buffers,
10 conexões e cerca de 646MiB disponíveis na observação após start. HBA foi corrigido;
migrate/replay, fixture, index/assets/findings e relatório passaram. Reader consultou
as 4 avaliações e foi corretamente impedido de UPDATE. Não é necessário repetir as etapas 1–6.
[Aceite e limites](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md).

A API/store /root/p01/store-v05e-r1 não integra a fixture de recuperação. Dados aprovados:
base canca_p01_lab_r1, fixture /var/lib/canca/postgres-lab/P01-PG-R1-06230404e329/server-store.

Próximo teste do operador: [recuperação R1 v0.6.7](LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md),
com base destino nova canca_p01_restore_r1. Helper capture/verify só lê banco/store;
backup/restore e replay no destino são ações explícitas do roteiro. Não usar harness CI no LAB.

[Relatório v0.6.5](ASSESSMENT_REPORT_v0.6.5.md) · [Backup/restore CI v0.6.6](BACKUP_RESTORE_v0.6.6.md).
