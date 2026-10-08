# Cancã — legado revisado e relatórios históricos v0.6.28

08/10/2026 (-03). CANDIDATE opt-in em banco isolado, schema9.
[ADR0042](ADR_0042_Workspace_Legacy_v0.6.28.md).
O listener atual exige9; os contratos qualificados v0.6.26/schema7 e
v0.6.27/schema8 permanecem reproduzíveis nos commits anteriores.
As tarefas1–3 integradas e a reconciliação da PR #138 são preservadas.

## Fonte e autorização

O administrador vincula explicitamente assessment → workspace antes da leitura.
Não deduzir ownership por nome, CIDR, node ou workspace aberto. Esta ponte aceita
imports já indexados/projetados pelo contrato legado schema4; não indexa fontes
ausentes nem completa automaticamente análises. A categoria observada continua
`identity`, com as decisões manuais e `evidence_only` do modelo v0.6.25.

`LegacySources` é configuração privada do servidor, por assessment. Pode apontar
assessments distintos ao mesmo store original somente para leitura. O SQL resolve
o mapping da base autorizada antes de qualquer acesso aos bytes; o cliente fornece
somente bundle_id. Paths canônicos, sem symlinks/traversal, e replay do bundle,
receipt e hashes confirmam a identidade. Os stores novos por workspace continuam
fisicamente disjuntos em `SourceRoots`. Nenhum arquivo original é reescrito.

A função privada `workspace_legacy_snapshot(text)` retorna apenas o bundle ligado
ao mapping da base ativa, sob grants atuais e lease/generation. Atores não recebem
SELECT direto nas tabelas legadas compartilhadas. O migrator/owner confiável é
separado dos atores; owners/BYPASSRLS não são identidades humanas do listener.
Manutenção concorrente das tabelas/fontes legadas não integra o contrato: congelar
a fonte durante a migração revisada. Os produtores antigos recusam schema9.

## Prévia, aplicação e relatório

| Operação | Contrato |
| --- | --- |
| Prévia | Verifica bytes, projeções, contagens, referências, IDs e catálogo histórico. Guarda planos imutáveis sob RLS, sem publicar inventário/histórico ou incrementar revisão. |
| Aplicação | Revalida fonte, snapshot e revisão da prévia. Identidade, observações, cópia histórica e recibos são uma transação/uma revisão; falha ou perda do lease antes do commit reverte o conjunto. |
| Reconciliação | Mesmo plan_id/request_id devolve o recibo confirmado, mesmo após mudança de revisão ou perda da fonte. Payload diferente com o mesmo request_id é conflito. |
| Relatório | Consulta a cópia histórica de um bundle, sem store ou engine corrente, com revisão atual, migrated_revision, hashes, análise/catalogue e avaliações originais. |

A prévia reutiliza o plano de identidade existente e depois confirma a cerca do
legado. Uma corrida pode deixar um plano de identidade não utilizado, protegido
por RLS; não deixa um backfill parcial. Ambiguidade mantém `review_required` e
impede apply até nova prévia com decisão explícita.

Os IDs legados de assets/findings, engine/catalog hashes, resultados e proveniência
são preservados; objetos workspace recebem IDs próprios. Links por ordinal mostram
o asset antigo e o objeto novo quando disponíveis. `evidence_only` conserva as
avaliações sem associar objetos. Não há execução da engine de findings corrente.
Ausência de análise resulta em `not_analyzed`, nunca em resultado limpo; outcomes
`insufficient_evidence`, `not_applicable` e `not_supported` permanecem distintos.
Nenhum finding é fechado automaticamente. O tempo é o recebimento do import;
tempo de coleta não é inferido.

| Método em /api/v1/workspaces/{id} | Entrada |
| --- | --- |
| POST legacy/preview | generation, bundle_id; mode/categories/decisions/site_id/environment_id opcionais. |
| POST legacy/apply | generation, plan_id, request_id. |
| GET legacy/{bundle_id}/report | generation; limit, after_ordinal, expected_revision, expected_scope_sha256 opcionais. |

Decisions usa chaves JSON ordinais canônicas como na API v0.6.26. A paginação
retorna `next_after_ordinal`, `revision` e `report_scope_sha256`; continuação exige
os dois últimos valores e falha se a revisão/escopo mudar. Limites:100 avaliações
por página,2.000 por bundle,1.000 observações,1.024 artefatos e4MiB no snapshot.
O resumo conta o bundle completo; esta rota não é um agregado de todo o workspace
nem uma exportação JSON/Markdown/ZIP. Auth, logout, deadlines e controle de workers
continuam os da API humana; operações/preparo são jobs do coordenador.

Erros específicos:404 para fonte não mapeada/disponível, plano ou relatório ausente;
409 para snapshot/escopo/revisão alterados ou revisão manual pendente;400 para
entrada inválida;403 para grant negado. Erros de integridade/preparo e indisponibilidade
do banco são redigidos; não retornam paths/DSNs. Após resposta perdida, repetir o
mesmo request_id para reconciliar o commit, sem gerar outro ID automaticamente.

## Provisionamento de desenvolvimento

Com o coordenador parado, manutenção aplica somente a migração aditiva9:

```sh
python persistence/P01_Workspace_Legacy.py migrate
python persistence/P01_Workspace.py bind-assessment --workspace-id BASE --assessment-id LEGACY
```

Além das permissões qualificadas do modelo/registry, conceder explicitamente:

```sql
GRANT SELECT ON canca.workspace_legacy_plans,canca.workspace_legacy_imports TO canca_reader,canca_writer;
GRANT INSERT ON canca.workspace_legacy_plans,canca.workspace_legacy_imports TO canca_writer;
GRANT EXECUTE ON FUNCTION canca.workspace_legacy_snapshot(text) TO canca_reader,canca_writer;
```

Binding v1 mantém os campos existentes e aceita o campo opcional abaixo, somente
no arquivo privado do servidor; não é entrada HTTP:

```json
"legacy_sources": {"LEGACY": "/srv/canca/legacy/store"}
```

Não alterar SQL1–8/checksums nem usar roles privilegiadas para o listener. A CLI
Recovery `migrate` continua pinada em8; `inspect`/`prepare-restored` verificam o
prefixo9 quando presente. `migrate` legado não faz backfill automático. Retorno à
versão anterior exige o conjunto de recuperação verificado; sem down-migration.

## Qualificação e limites

CI dedicado executa os contratos antigos e a ponte em PostgreSQL16/17. O harness
guardado conserva o restore schema8 e adiciona um restore schema9 com30 tabelas,
store original, IDs/avaliações, relatório, recibos, RLS/ACL e próxima revisão.
Usa mesmo cluster/major e roles sintéticas existentes; não qualifica recuperação
cross-cluster de roles/segredos/certificados ou operação no LAB.

Audit HTTP workspace, migração completa/categorias adicionais, adapters de jobs
legados, UI/Mapper e recovery operacional continuam pendentes. R01–R06/T13/R20
seguem parciais; Alpha aberta. Nenhum teste humano ou mudança do LAB solicitado.
