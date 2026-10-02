# P01 — Próximos passos da Product Alpha

Atualizado em 02/10/2026 (-03), após v0.6.5 e resultados do soak estendido.

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
históricas, com paginação consistente. Todas as funções PostgreSQL
permanecem **CANDIDATE para LAB**, com CI sintético em PostgreSQL 16/17 real.

Não instale PostgreSQL nem altere o store atual por causa deste guia. A qualificação
do servidor terá um roteiro separado para base isolada, contas, TLS e backup/restore.
Nenhuma migração é automática. O próximo desenvolvimento independente é a
fixture e validação de backup/restore do par banco/store, antes da UI. Resolução manual e
continuidade de IDs entre assessments terão decisões próprias.

[Findings v0.6.4](FINDINGS_v0.6.4.md) ·
[Assets v0.6.3](ASSET_REGISTRY_v0.6.3.md) ·
[Lifecycle v0.6.2](ASSESSMENT_LIFECYCLE_v0.6.2.md) ·
[Integração v0.6.1](INGESTION_INDEX_v0.6.1.md) ·
[R1 curto](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md)

## Diagnóstico PostgreSQL recebido

Rocky 10.2/Python 3.12.13, 1 GiB de RAM (~648 MiB disponíveis), 26 GiB livres,
sem ferramentas no PATH nem units PostgreSQL listadas. Store ativo identificado:
/root/p01/store-v05e-r1. A qualificação usará base/store separados e configuração
para LAB pequeno; não altera a API ativa. Sem novo diagnóstico solicitado aqui.

[Relatório v0.6.5](ASSESSMENT_REPORT_v0.6.5.md).

[Roteiro LAB PostgreSQL R1](LAB_POSTGRESQL_R1_v0.6.5.md): executar primeiro as
etapas 1–3 (PostgreSQL 16 nativo/local e memória); fixture offline e reader seguem
preparados nas etapas seguintes. Desenvolvimento de código continua independente.
