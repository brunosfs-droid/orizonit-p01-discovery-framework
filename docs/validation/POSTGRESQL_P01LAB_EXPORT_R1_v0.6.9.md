# Cancã — aceite do exportador PostgreSQL R1 v0.6.9

02/10/2026 (-03). **LAB VALIDATED no cenário sintético R1 do Rocky.**
Cinco capturas fornecidas pelo operador foram inspecionadas. Não houve acesso
ao host nem recebimento do TAR. O aceite funcional baseia-se na execução e nos
resultados visíveis. Os arquivos `report.md` e `report1.md` recebidos depois
fecham a revisão de conteúdo e estrutura GFM da apresentação técnica do R1.

## Evidências

| Captura | Resultado observado |
| --- | --- |
| 014025 | Windows usa revisão d1b32cf6d6185e87fc4a08abb57654c29d8e8c4b, gera TAR/SHA256 e conclui SCP para o Rocky |
| 014007 | Instalador corrigido permite pasta opcional, verifica hashes do módulo/engine e imprime `EXPORTADOR OK — engine original preservado`; instalação da sessão `true` |
| 014149 | Execução de duas exportações com páginas 1 e 100, na base `canca_p01_restore_r1`, e verificador de arquivos/contagens/permissões |
| 014138 | Duas respostas `status: exported`, versão `0.6.9`, assessment `P01-PG-LAB-R1`, quatro avaliações e dois diretórios distintos; `POSTGRESQL LAB EXPORT PASS` |
| 014247 | `PGPASSWORD` removido da sessão; `Exportacao validada nesta sessao: true` |

## Escopo aceito

- Deployment `/root/p01/canca-postgres-lab-v0.6.5`, ambiente virtual existente.
- Base recuperada `canca_p01_restore_r1`, assessment sintético `P01-PG-LAB-R1`.
- Raiz de exportação `/var/lib/canca/report-exports`, fora do store.
- Instalação aceita o arquivo esperado e a pasta opcional gerada pelo Git,
  verifica o módulo qualificado e preserva o engine original.
- Duas saídas completas JSON/Markdown/manifesto/sidecar em diretórios distintos.
- Verificador PASS demonstra hashes/tamanhos/sidecar e permissões 0700/0600.
- Lifecycle `completed`, revisão 4; 1 CAS/2 observações; 4 avaliações, com
  2 `finding` e 2 `no_finding`; 2 ocorrências históricas permanecem `Open`.
- Quatro páginas versus uma página de dados, consulta terminal vazia verificada,
  igualdade semântica entre saídas sob o mesmo hash de escopo.
- Respostas registram `database_mutated=false` e `source_bytes_revalidated=false`.

As linhas anteriores sobre contagens, igualdade, hashes e permissões referem-se
às assertions do verificador que chegou ao PASS. Não são uma comparação
independente dos arquivos por este revisor. A captura do Windows mostra hash do
TAR; estas cinco imagens não mostram um novo `sha256sum` do TAR no Rocky, portanto
não se atesta igualdade independente do TAR entre hosts. O hash do módulo
instalado foi verificado pelo bloco que passou.

## Revisão dos arquivos Markdown

Os dois anexos são idênticos byte a byte: 3176 bytes cada, SHA256
`d3b8bba49aaad8805c8760d5e276bf504d76f2425f16dfca5dfcbf0f864133f6`.
Recebimento e revisão em 02/10/2026 (-03), após as cinco capturas acima.

- Parser GFM `marked`: quatro tabelas válidas; resumo com oito campos,
  cobertura com cinco resultados, pendências com uma linha e histórico com
  quatro avaliações em sete colunas. Sem links ou HTML ativo na saída analisada.
- Contagens consistentes com o ensaio: lifecycle `completed`, revisão 4,
  2/2 imports analisados, 1 CAS/2 observações, 2 `finding`/2 `no_finding`,
  duas ocorrências históricas `Open` e nenhuma pendência de projeção.
- IDs, caminhos e hashes estão completos; entidades numéricas preservam o
  texto escapado. Escopo
  `4e0c0886ab99e420893bee2253055f6a13bdada8dfda539bc26861eb328f7169`.
- Limites administrativos, histórico, metadados persistidos e cerca de escopo
  estão explícitos; o relatório não afirma remediação ou segurança do ambiente.

Apresentação técnica aceita por inspeção de conteúdo e parsing GFM, sem
qualificação de um renderizador gráfico específico ou de PDF/impressão.
A tabela histórica é larga por preservar IDs/SHA256 completos; a leitura pode
exigir rolagem horizontal conforme o visualizador. Não há truncamento nos anexos.
JSON e manifestos não foram anexados: identidade entre os dois Markdown foi
verificada independentemente, mas seu vínculo com cada diretório/manifesto segue
baseado no PASS mostrado nas capturas. Não publicar os anexos automaticamente.

## Limites e continuidade

Este aceite substitui a pendência funcional das tentativas bloqueadas anteriores.
Não repetir envio/instalação, exportação, restore ou lifecycle para fechá-lo.
Preservar os dois diretórios gerados para rastreabilidade.

O gate de apresentação técnica do R1 está fechado. Não qualifica produção, exportador Windows,
TLS remoto PostgreSQL, roles completos, autenticação de operadores/API Web ou
autorização de nodes v0.6.10. Conta utilizada neste ensaio foi `canca_lab_admin`;
o aceite não substitui a qualificação própria de uma role SELECT-only no host.

[Roteiro executado](../LAB_POSTGRESQL_EXPORT_R1_v0.6.9.md) ·
[Tentativas anteriores](POSTGRESQL_P01LAB_EXPORT_ATTEMPT_R1_v0.6.9.md) ·
[Semântica e limites](../REPORT_EXPORT_v0.6.9.md).
