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
