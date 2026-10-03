# Cancã — exportação consolidada v0.6.9

**LAB VALIDATED para exportação funcional no R1 sintético Rocky.** Cinco capturas
demonstram instalação corrigida, duas exportações e PASS do verificador de
contagens/hashes/permissões. Conteúdo e estrutura GFM da apresentação técnica
aceitos nos dois anexos Markdown idênticos; sem qualificação de PDF/renderizador.
[Aceite e limites](validation/POSTGRESQL_P01LAB_EXPORT_R1_v0.6.9.md).

## Operação

CLI local, schema mínimo 4, Python 3.12+, driver PostgreSQL opcional já utilizado.
Conta com USAGE no schema e SELECT nas dez tabelas do relatório v0.6.5. Não exige
INSERT, UPDATE, DELETE, CREATE ou acesso aos bytes do store. Configuração explícita
PGHOST/PGDATABASE/PGUSER; credenciais externas ao comando, como no relatório existente.

Crie uma raiz privada de saída **fora do store de evidências**, de preferência um
diretório dedicado. A raiz precisa existir e não pode usar symlinks/aliases.

```bash
mkdir -p /var/lib/canca/report-exports
chmod 700 /var/lib/canca/report-exports
python persistence/P01_Report_Export.py \
  --assessment-id P01-PG-LAB-R1 \
  --output-root /var/lib/canca/report-exports --page-size 100
```

Resultado `exported`, exit 0 e `export_dir` com caminho real da nova execução.
`--page-size 1` facilita qualificar o caso paginado R1; o tamanho não altera o
conteúdo das avaliações consolidadas. Cada execução gera um diretório diferente.
O exportador não conhece a localização do store: a raiz externa é escolha explícita
do operador. Não use caminhos de evidência como destino de exportação.

| Arquivo | Conteúdo |
| --- | --- |
| report.json | Metadados completos do relatório, avaliações ordenadas, catálogo histórico, recomendações e referências |
| report.md | Apresentação de lifecycle, cobertura, pendências e todas as avaliações; detalhes completos no JSON |
| manifest.json | Tamanho/SHA256 do JSON e Markdown, ID/escopo/versionamento |
| manifest.json.sha256 | SHA256 dos bytes do manifesto |

No Linux, diretório 0700 e arquivos 0600. Os arquivos são escritos numa área
temporária privada da raiz, sincronizados e publicados juntos por rename de
diretório no mesmo filesystem. Falha tratada remove somente a área desta execução.
Interrupção abrupta pode deixar `.P01-EXPORT-*`; não reutilizá-la como exportação concluída.
Não há sobrescrita de uma execução anterior. Permissões/garantias de filesystem
em Windows ainda não foram qualificadas para o exportador.

## Consistência e semântica

Cada página usa a API canônica `show_assessment` numa transação REPEATABLE READ READ ONLY.
Todas as continuações e uma consulta terminal vazia usam o SHA de escopo da primeira
página. Mudanças normais de imports/lifecycle/projeções bloqueiam com `report_scope_conflict`.
Sem retry silencioso: refazer explicitamente após estabilizar o assessment.
Não é uma única transação cobrindo toda a exportação, snapshot durável ou proteção
contra alteração SQL direta por DBA. Uma escrita após a última consulta pertence
a uma observação posterior e não invalida retroativamente o arquivo gerado.

Antes de escrever, verifica ordem estrita/ausência de duplicatas, cursor, cabeçalho,
contagem total, resultados por regra e contagens por análise. Limites herdados:
100 imports, 10.000 observações/avaliações, páginas 1–100. Máximo 32 MiB por JSON/Markdown
e 32 MiB acumulados de registros serializados; exceder limites falha sem truncar.
Dados textuais persistidos são escapados no Markdown para evitar links/HTML ativos.

`source_bytes_revalidated=false`: lê o histórico persistido, sem abrir o store ou
reexecutar regras. O catálogo histórico continua válido mesmo se o catálogo atual
mudar. Evidência bruta/credenciais de conexão não entram no arquivo. Metadados,
IDs, caminhos relativos e evidência extraída persistida podem exigir controle de
acesso; a exportação é local privada e não publica arquivos automaticamente.

Findings são ocorrências históricas. Runs com `no_finding` não encerram ocorrências
anteriores; lifecycle `completed` é administrativo. `no_imports`, análises pendentes,
`insufficient_evidence`, `not_applicable` e `not_supported` permanecem explícitos.
Sem alegação de ambiente saudável, cobertura integral, vulnerabilidades únicas ou
remediação. Não inclui histórico de eventos do lifecycle; inclui seu estado/revisão
como no relatório v0.6.5. Sem nova migração, endpoint HTTP, autenticação ou RBAC.

Falha: JSON com código fixo, exit 2; sem DSN/exceção bruta. ID ausente retorna
`assessment_not_found` e nenhum diretório de exportação. Hashes detectam divergência
dos arquivos, não autenticam autoria nem substituem controle de acesso/backup.

[ADR 0020](ADR_0020_Report_Export_v0.6.9.md) ·
[Aceite lifecycle](validation/POSTGRESQL_P01LAB_LIFECYCLE_R1_v0.6.8.md).

## Instalação e teste R1

[Roteiro do exportador](LAB_POSTGRESQL_EXPORT_R1_v0.6.9.md): instala somente o módulo
novo, preserva o engine original e qualifica duas saídas privadas. PR #106 integrado
(d1b32cf6d6185e87fc4a08abb57654c29d8e8c4b) escapa também a pontuação de URLs simples
no Markdown. JSON e semântica do relatório preservados.

As capturas 235251/235559/235634/235648 mostram bloqueio de instalação no roteiro
anterior, antes da consulta ao banco. [Diagnóstico e limites](validation/POSTGRESQL_P01LAB_EXPORT_ATTEMPT_R1_v0.6.9.md).
As capturas posteriores 014007/014025/014138/014149/014247 substituem a pendência
funcional: instalação `true`, dois JSONs `exported`, verificador PASS e exportação
da sessão `true`. [Aceite R1](validation/POSTGRESQL_P01LAB_EXPORT_R1_v0.6.9.md).
Não repetir instalação/exportação, restore ou exercise. Os anexos `report.md` e
`report1.md` fecharam a revisão de conteúdo/estrutura GFM desse gate de relatório.
