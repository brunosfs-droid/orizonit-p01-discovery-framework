# P01 — Próximos passos da Product Alpha

Atualizado em 02/10/2026 (-03), após v0.6.2 e resultados do soak estendido.

## Preciso testar alguma coisa agora?

**Nenhum teste seu bloqueia o desenvolvimento atual.** R1 curto e soak estendido
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
com revisão, idempotência e histórico transacional. Todas as funções PostgreSQL
permanecem **CANDIDATE para LAB**, com CI sintético em PostgreSQL 16/17 real.

Não instale PostgreSQL nem altere o store atual por causa deste guia. A qualificação
do servidor terá um roteiro separado para base isolada, contas, TLS e backup/restore.
Nenhuma migração é automática. O próximo desenvolvimento independente é a
modelagem de identidade persistente de assets, antes de findings e UI.

[Lifecycle v0.6.2](ASSESSMENT_LIFECYCLE_v0.6.2.md) ·
[Integração v0.6.1](INGESTION_INDEX_v0.6.1.md) ·
[R1 curto](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md)
