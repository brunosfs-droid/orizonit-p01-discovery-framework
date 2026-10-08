# Cancã v0.6.38 — R01/R03 legacy readiness (candidate)

Status **candidate em branch**. Dependência de base: `main` no commit
`00616325a0a90b9d3d1565b1617b34ed2fc88050` (v0.6.36).
A PR #148 (E0/recovery preflight v0.6.37) é independente e continua sujeita
aos gates de integração. Este incremento não altera o schema9, migrações,
collectors, stores, engine de análise histórica ou jobs.

## Problema

O import legado já tinha `legacy/preview` e `legacy/apply`, com mapeamento
explícito assessment→workspace e histórico preservado. Faltava ao operador uma
leitura autenticada e restrita que indicasse se **um** bundle historicamente
indexado pode entrar na fase de preview, ou se já há comprovante imutável de
backfill da **mesma** origem. Não se pode inferir migração concluída pela simples
presença de registros/IDs iguais entre workspaces.

## Contrato

`GET /api/v1/workspaces/{workspace_id}/legacy/{bundle_id}/readiness?generation=N&expected_revision=R`

- Autenticação via token humano existente, leitura `workspace:read` somente;
  `expected_revision` opcional para primeira leitura, recomendado para impedir
  resultado stale quando operador mantém contexto fixo.
- Primeiro se obtém `workspace_legacy_snapshot` sob SQL/RLS, vinculado ao
  assessment mapeado; **antes** de ler o original em disco. O servidor seleciona
  uma raiz privada pelo assessment autorizado, nunca aceita path/role do cliente.
- A projeção/receipt/finding historical e a igualdade entre snapshot SQL e
  origem são verificadas. Uma segunda leitura SQL faz a conferência após I/O.
  Compare workspace+collection+assessment+source digest+snapshot persistidos
  em `workspace_legacy_imports`.
- Retorna `preview_required` ou `already_backfilled`, revisão, contagens
  sanitizadas, `source_integrity=verified_at_read`, `identity_scope=identity_only`,
  `automatic_apply=false` e `migration_complete=false`.
- Nenhuma escrita, chamada ao scanner, promoção de identidade, backfill automático,
  reexecução de findings ou autorização de merge por esse endpoint.
- Conflito/drift de fonte, revisão e permissão falham fechado. Auditoria privada
  fixa `legacy_readiness`, sem bundle ID, query, credenciais ou paths.
- Um `already_backfilled` **não** diz que todas as avaliações e categorias
  foram migradas; é pontual para aquele bundle e snapshot.

## Critérios de qualificação

1. Testes negativos de versão, entrada e snapshot antes do banco.
2. PostgreSQL 16/17: reader A antes/depois de apply; nenhuma escrita pela leitura;
   drift revision; origem modificada e role B/revogada negadas antes de I/O.
3. HTTP real: 200 em fonte válida, 400 sem generation/query extra, 409 com
   revision stale. Auditoria de operação fixa, sem dados pessoais/IDs.
4. CI do último HEAD (Python CI, Workspace Foundation PG16/17, PostgreSQL CI,
   CodeQL e regressões) aprovado antes de integração.
5. E0 LAB continua pendente: provar autorização, receipts e conteúdo do
   store sobre cluster isolado. Não repetir os R1 antigos aprovados.

## Limitações e próximos incrementos

R01/R03 **permanecem parciais**: esta verificação cobre apenas um bundle do
legado schema4 já indexado, com category `identity`. Não enumera todas as
origens históricas, não indexa arquivos ausentes, não migra compute/network/
services e não faz processamento em lote. Migração ampla exige catálogo
autorizado de fontes, backfill por categorias e reconciliação com recusas por
colisão, sob RLS e revision fence. R02 (adapters de jobs/scanners) e R04/R05
(relações observadas/importação seletiva) continuam nas próximas PRs.
