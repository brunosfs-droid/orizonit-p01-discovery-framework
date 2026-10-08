# Cancã — Workspace Category Reader v0.6.30 (incremento inicial)

Primeiro incremento opt-in após a integração da v0.6.29. Leitor **interno e
read-only**, executado sobre o `model.list_objects` já autorizado e com
revision fence. Sem nova rota HTTP, migração SQL ou reader de scanner neste lote.

- Categorias fixas: compute (host), network (device/interface/network/vlan),
  services (service/group) e components (component/passive).
- Varre páginas ordenadas de 100 objetos, no máximo dez páginas (1.000 itens
  examinados), sem paginar silenciosamente além da cota. Resposta
  `complete=false` e `next_after` indicam que há objetos ainda não lidos.
- As páginas subsequentes usam a revisão da primeira; alteração concorrente
  causa rejeição pelo modelo. Workspace e generation são validados pelo modelo.
- A seleção é por tipo **declarado no cadastro**; não atribui identidade,
  categoria observada, compatibilidade de vendors nem ausência de ativos.
- Não altera origens, objetos, relações, sinais, recibos, permissões ou schema9.

## Próximo passo de implementação

Qualificar o leitor por integração PostgreSQL 16/17 e escolher a exposição HTTP
com cursor e revision fence, antes de UI/Mapper. O reader de categorias observadas
na ingestão e o backfill completo ainda são gates abertos. R01–R06 não estão
concluídos, e recuperação cross-cluster permanece pendente.

## Integração inicial à API

GET /api/v1/workspaces/{workspace_id}/categories/{compute|network|services|components}?generation=N&expected_revision=R&max_pages=P.
Requer sessão autenticada, workspace aberto e grant workspace:read. Resposta parcial mantém complete=false e next_after; não há continuação HTTP direta baseada no cursor neste incremento. Auditoria registra somente category_read, sem caminho ou query. Cobertura SQL/HTTP de ponta a ponta permanece gate antes de merge.

## Continuação de paginação

Se a resposta contiver `complete=false`, o cliente deve repetir o GET com `after=next_after`, **a mesma categoria, geração e `expected_revision=revision`** retornada. Cursor não é autoridade, não transfere grants e não ignora o fence. Mudança de revisão impede a retomada e exige reiniciar a leitura. Sem `after`, a revisão pode ser capturada na primeira página.

## Qualificação SQL acrescentada

O workflow Workspace Foundation CI (PostgreSQL 16/17) agora compila o reader, executa sua suite unitária e exercita por SQL real os readers via WorkspaceService: categorização declarada, revisão expirada, role read-only, grant revogado, troca A/B e token antigo. Estes testes são evidência de isolamento sintético, não substituem o restore cross-cluster nem o LAB real.

## Dez entregas deste lote

1. Qualificação do CI anterior (oito workflows PASS).
2. Filtro opcional por site_id, após leitura autorizada.
3. Filtro opcional por environment_id, após leitura autorizada.
4. Combinação AND de site/ambiente sem inferir identidade.
5. Validação estrita dos filtros antes do banco.
6. Whitelist HTTP dos parâmetros sem aceitar caminhos arbitrários.
7. Contagem explícita de objetos varridos (scanned).
8. Contagem explícita de correspondências (matched).
9. Preservação do cursor mesmo em páginas filtradas vazias.
10. Testes de filtro, paginação e rejeições na suite unitária e HTTP.

Os filtros são locais ao conjunto limitado de objetos lidos, **não** uma consulta
SQL otimizada por site; complete=false não permite inferir ausência de objetos.
O cursor deve conservar categoria/site/ambiente entre as chamadas, com revisão
fixa; valores de filtros não são copiados para o audit log. Continuam pendentes
leitores de sinais observados, integração real de scanners e recuperação em LAB.

## Lote de qualificação e refinamento seguinte

A revisão 30fd559 passou integralmente nos oito workflows de PR (incluindo Workspace Foundation PG16/PG17).
O incremento posterior inclui filtros opcionais kind/origin, combináveis com site/ambiente, com enumeração fechada e kind restrito à categoria selecionada. Linhas provenientes do model são validadas (tipo/origem/revisão/localizações/label) antes de retornar objetos. Todos os filtros continuam após a leitura autorizada, sem claims de inventário completo. Os testes unitários e HTTP cobrem dados malformados e parâmetros duplicados/fora de escopo.

## Gates adversariais adicionais

Suite de 16 cenários extras cobre: partição de tipos; filtros combinados; página terminal vazia; revisão zero; limite com zero matches; token B contra A; limites não inteiros; categorias de tipo inválido; cursor não canônico; has_more estrito; duplicidade; origem sem reclassificação; projeção sem campos extras; metadados ausentes; resposta cross-workspace; e drift entre páginas. Esses cenários são sintéticos e não substituem tests de SQL real.
