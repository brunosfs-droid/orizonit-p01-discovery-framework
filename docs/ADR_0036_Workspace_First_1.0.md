# ADR 0036 — workspace isolado, carga única e 1.0 orientada a infraestrutura

Data: 06/10/2026 (-03). Decisão de produto aceita pelo mantenedor.
Detalhamento arquitetural: baseline de implementação; runtime ainda não alterado.
Substitui a classificação post-1.0 de inventário/Mapper/dependências em MVP,
roadmap, governança e sequência da ADR 0021. Preserva licença e registros históricos.

## Contexto

A base tem assets/observações e grants por assessment, não por workspace.
PostgreSQL/filesystem são fronteiras independentes. Sites só existem dentro de
workspace; objetos de bases distintas nunca interagem. Várias bases salvas, uma
carregada por vez. Mapper/serviços são requisitos 1.0, com scans explícitos.

## Decisão

1. Workspace é a fronteira de dados. Sites pertencem diretamente a ele;
   ambientes são recortes opcionais. Organization é metadado.
2. Uma instalação admite um workspace ativo para operações de produto.
   Registro leve de nomes/IDs/grants não carrega inventários fechados.
3. Todo endpoint/tarefa/consulta/cursor/cache/download/catálogo privado/secret
   verifica workspace e grant. Seleção visual não substitui autorização.
4. PostgreSQL continua com IDs/chaves compostas; RLS reforça isolamento sem
   substituir grants/API. Paths particionados, bytes históricos preservados.
5. Observação imutável + declaração versionada + projeção atual.
   Relationship liga objetos da mesma base; inferência guarda regra/evidência,
   alternativas e confiança.
6. Import tem diff/política/categoria/cobertura e commit fenced por revisão.
   Nunca merge só por IP, silent overwrite ou remoção por coleta parcial.
7. Grafo relacional alimenta camadas/submapas/serviços, sem novo banco de grafos.
   UI consulta páginas/subgrafos limitados.
8. Administração do servidor e Visão geral do workspace têm rotas/rótulos/grants
   distintos. Nenhum mapa agregado entre workspaces.
9. Standalone preservado; login humano, grants e Node mTLS são controles distintos.

## Carga e encerramento

Estados propostos: `closed`, `opening`, `open`, `closing`, `recovery_required`.
Coordenador da instalação mantém lease de workspace e generation de tarefas.
Troca: bloquear admissões → concluir/cancelar cooperativamente → reconciliar
intent/commit → invalidar generation/cursors/URLs/respostas → liberar caches
→ fechar → abrir próxima base. Import em commit não é interrompido no meio;
timeout/falha conserva revisão e bloqueia troca insegura.

Multiaba/multiusuário não abre segundo workspace. Pedido incompatível informa
“workspace em uso” sem revelar dados a quem não tem acesso. Troca exige grant;
superadmin não recebe leitura automática de conteúdo. Reinício não retoma scan,
autenticação ou POST. Backups/restores são manutenção limitada com snapshot/locks,
sem carregar segundo grafo na UI.

## Consequências

Carga única limita paralelismo entre clientes intencionalmente. Não implica
carregar toda base em RAM nem garante desempenho sem benchmark. Filtrar somente
no browser é insuficiente. Banco por workspace aumenta custo de operação neste
estágio; usar schema compartilhado, constraints/RLS e store particionado.

Adicionar fundação em v0.6.x, UI/Mapper em v0.7 e inteligência em v0.8. Opt-in
até migração/grants/isolamento qualificados. Request legado não escolhe workspace
ativo implicitamente. [Gates](TEST_PLAN_1.0.md): adversarial A/B com IDs/IPs iguais,
SQL/API/store/export/restore, lease/process-exit, PG16/17 e benchmark de trocas.
