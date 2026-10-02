# P01 — Status técnico da integração v0.6.1

Data: 02/10/2026 (-03). Estado: **CANDIDATE para LAB**. Refs #63.

## Entregue

- API `--metadata-index postgres`, default off, após o mesmo import canônico.
- Estado de índice explícito no POST e no GET autorizado; acknowledgment de
  filesystem preservado em HTTP 201/200.
- Fonte e identidade verificadas antes da conexão; erros fixos sem credenciais.
- Uma conexão/transação por tentativa; no banco, replay e locks da fundação v0.6.0.
- Reconciliação explícita de um import usando `index-import`; nenhum sweep ou retry.
- Cleanup de staging sob o lock para proteger requests duplicados concorrentes.
- Testes de interrupção depois dos arquivos e depois do DB commit antes da resposta.

## Qualificação

Regressões e casos PostgreSQL 16/17 devem passar no CI antes da integração. O
registro consolidado identifica SHA, runs, jobs e resultados efetivamente obtidos.
A versão continua CANDIDATE: servidor PostgreSQL do operador, TLS, contas e
backup/restore ainda não foram homologados no LAB.

Runtime v0.5e.6, wrapper v0.5f.0, scheduler v0.5f.3 e schema/migração PostgreSQL
0001 permanecem preservados. O soak estendido iniciado pelo operador é um gate
separado; esta versão não declara seu aceite antes das evidências finais.

## Próximos passos

Lifecycle do assessment e controle de transições, com ADR e contratos próprios,
antes de acrescentar identidade persistente de assets, findings, API/UI e reporting.
Qualificação PostgreSQL do LAB segue com roteiro isolado em momento apropriado.

Novos documentos corporativos são arquivados em OneDrive/SharePoint, conforme a
mudança autorizada. Google Drive permanece legado; migração geral é independente.

[Guia](INGESTION_INDEX_v0.6.1.md) · [ADR](ADR_0012_Ingestion_Index_v0.6.1.md)
