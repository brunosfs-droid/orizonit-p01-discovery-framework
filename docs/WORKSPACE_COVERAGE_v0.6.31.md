# Cancã v0.6.31 — Categoria e cobertura de objetos registrados

## Contrato

GET /api/v1/workspaces/{workspace_id}/categories/{category}/coverage?generation=N&expected_revision=R&after=CURSOR&max_pages=P

A rota exige sessão, grant workspace:read e workspace aberto, com revision fence.
Filtros opcionais: site_id, environment_id, kind e origin (enums/IDs fechados).
Retorna total matched, scanned, contagens por kinds e origins, complete e next_after.
Com complete=false, as contagens **não** representam o total do workspace;
para continuar, repetir com a mesma revision e after=next_after, agregando
somente resultados de revisões idênticas. collection_coverage=not_assessed;
nenhum scanner ou inferência de cobertura real de rede é executado.

Não há migration, novos privilégios SQL, dados secretos, campos dinâmicos nem
mudanças no legado. Audit: category_coverage, sem query/IDs do recurso.
O próximo gate é leitura de atributos/sinais observados com fonte comprovada,
migração de categorias e recuperação operacional multi-componentes.
