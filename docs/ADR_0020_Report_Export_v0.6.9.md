# ADR 0020 — exportação do relatório consolidado

02/10/2026 (-03). Decisão implementada; exportador funcional **LAB VALIDATED
no R1 sintético Rocky**. Apresentação técnica aceita por conteúdo/parsing GFM
dos dois anexos idênticos, sem qualificação de PDF/renderizador específico.
[Aceite e limites](validation/POSTGRESQL_P01LAB_EXPORT_R1_v0.6.9.md).

O relatório v0.6.5 já apresenta cobertura histórica/identidade/findings com páginas
consistentes. Lifecycle/paginação R1 v0.6.8 foi aprovado no destino recuperado.
É necessário um resultado local compartilhável, sem depender de uma superfície
API/Web cujo principal/autorização ainda não foram definidos.

Adicionar CLI separada `P01_Report_Export.py`, reutilizando exclusivamente as
consultas canônicas somente leitura. Não alterar engine/fingerprints ou migrações.
Consolidar todas as avaliações em JSON e Markdown, catálogo histórico e origem;
apresentar semântica histórica e pendências. Conferir fence em cada continuação
e na consulta terminal, ordem/contagens/hashes; bloquear sem exportação parcial.

Saída em raiz explícita existente sem aliases, diretório privado novo por execução.
Preparar todos os bytes antes de escrever; criar arquivos exclusivos 0600 numa
área privada 0700 e publicar o diretório completo por rename. Manifesto e sidecar
vinculam os bytes gerados. Não sobrescrever/reutilizar execuções. A raiz precisa
ficar fora do store, escolhido pelo operador; não há parâmetro store nem revalidação
dos bytes brutos. A área de saída deve ser controlada pelo mesmo usuário confiável.

Limites por avaliação/página/assessment e serialização impedem exportar resultados
truncados. A cerca cobre mudanças normais, não cria transação durável entre páginas
ou resistência a DBA. A semântica evita transformar lifecycle completed em correção
de findings ou zero ocorrências em saúde do ambiente. SHA256 é integridade, não assinatura.

Qualificar completeness, empty/pending, catálogo histórico, fontes indisponíveis,
escritor concorrente entre última página e verificação terminal, reader SELECT,
invariância de 14 tabelas/store, falha de disco, diretórios privados e texto hostil.
CI real PostgreSQL 16/17 e source tests; teste do Rocky é gate separado. A próxima
superfície requer decisão explícita de principal, escopo/tenancy e autorização.
