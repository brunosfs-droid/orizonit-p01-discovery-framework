# P01 — Status técnico v0.6.0

Data: 02/10/2026. Estado: **LAB VALIDATED — R1 básico sintético; escopo restante CANDIDATE**.

A Product Alpha começou pela fundação PostgreSQL do índice central de imports,
conforme issue #63 e ADR 0011. Não representa conclusão da fase v0.6.x inteira.

## Entregue

- CLI opcional `migrate`, `index-import`, `show-import`.
- Índice transacional de assessments, nodes, runs, imports e metadados dos artefatos.
- Migração versionada com checksum, idempotência, conflito sem overwrite e locks.
- Verificação do import/recibo/bundle antes da conexão; source somente leitura.
- Configuração de conexão externa, TLS verificado remoto e erros redigidos.
- CI com PostgreSQL 16/17 real, separado das verificações de Python e serviços nativos.

## Qualificação

A implementação deve passar os testes de source e as transações em serviços
PostgreSQL reais no CI antes do merge. A evidência consolidada identifica o commit,
os runs e os jobs efetivamente aprovados. A qualificação do servidor PostgreSQL no
LAB ainda está pendente; por isso a versão permanece CANDIDATE.

## Preservado

Runtime portátil v0.5e.6; wrapper v0.5f.0; scheduler v0.5f.3. Ingestão offline/mTLS e
store em arquivos continuam funcionando sem PostgreSQL. R2 distribuído passou;
o R1 curto do scheduler Windows/Rocky também passou. Soak estendido continua pendente.

## Próximos incrementos

1. Contrato de integração explícita entre ingestão e índice, com reconciliação da
   fronteira filesystem/banco e testes de interrupção (v0.6.1 proposta).
2. Lifecycle do assessment e identidade persistente de assets, com ADR próprio.
3. Findings/analyzer, API mínima, UI e reporting conforme prioridades da v0.6.x.
4. Qualificação PostgreSQL no LAB: contas separadas, TLS, backup/restore e rollback.

[Guia do componente](../persistence/README.md) · [Próximos passos](NEXT_STEPS_v0.6.0.md)

## Atualização de qualificação em 02/10/2026

O R1 básico em PostgreSQL 16.15 no Rocky passou: migração/replay, dois imports,
1 CAS/2 observações, 4 avaliações/2 findings históricos Open e leitura por reader
com UPDATE negado. [Aceite e 18 capturas](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md).
A observação nova substitui a pendência inicial de instalação e fixture. Não
qualifica API com índice, transições lifecycle, cursor/fence completo, TLS remoto,
roles de escrita separados ou restore operacional. Próximo gate: [recuperação R1](LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md).
