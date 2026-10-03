# Cancã — relatório executivo na Web v0.6.15

**CANDIDATE para LAB.** Desenvolvimento e CI independentes das validações manuais
adiadas pelo mantenedor em 03/10/2026 (-03). Nenhum teste no LAB é solicitado hoje.
Código qualificado em oito runs/16 jobs, com downloads reais nos dois tamanhos
de Chromium; [resultados e limites](validation/OPERATOR_WEB_EXECUTIVE_CI_v0.6.15.md).

A Web oferece dois downloads no assessment consultado. O novo botão
**Baixar relatório executivo (ZIP)** apresenta cobertura, identidade, findings
históricos e recomendações consolidadas em JSON/Markdown. Usa a síntese v0.6.14
sem alterar seu módulo ou CLI. O relatório técnico completo continua disponível.

## Uso e conteúdo

No novo listener Web, entre com a conta local já autorizada para o assessment,
consulte seu ID e escolha o download. Os dois botões usam o ID e o escopo da
consulta exibida; editar o campo de busca não muda o relatório já carregado.
Mesmo na primeira página, o arquivo considera **todas** as avaliações do escopo,
não só as linhas visíveis. Não é necessário percorrer as páginas antes de baixar.

| Download | Arquivos principais | Versão do conteúdo | Versão de entrega no manifesto |
| --- | --- | --- | --- |
| Técnico completo | report.json, report.md | 0.6.9 | 0.6.13 |
| Executivo | executive.json, executive.md | 0.6.14 | 0.6.15 |

Cada ZIP também contém `manifest.json` e `manifest.json.sha256`, com tamanhos e
hashes dos dois arquivos principais. Quatro membros fixos, sem compressão,
metadados ZIP fixos e nenhuma extração no servidor. O nome executivo é
`canca-{assessment}-executive.zip`; o técnico mantém seu nome e formato anteriores.
O [verificador técnico v0.6.13](validation/VERIFY_OPERATOR_WEB_EXPORT_v0.6.13.py)
continua compatível com o download técnico do novo listener.

As recomendações executivas vêm dos catálogos históricos, agrupadas por
regra/versão, policy, SHA256 do catálogo e SHA256 do engine. Todas as referências
de ocorrências ficam no JSON; evidência extraída/bruta e caminhos de fontes são
excluídos. Cobertura pendente/inconclusiva e revisão de identidade permanecem
explícitas. Uma coleta sem finding não encerra ocorrências anteriores; completed
continua sendo lifecycle administrativo. Não há score de risco ou remediação.
[Semântica completa](EXECUTIVE_REPORT_v0.6.14.md).

## Endpoint e limites

Existe somente no listener Web:

```text
GET /api/v1/assessments/{id}/report/executive/export?expected_scope_sha256={sha}
```

O SHA real tem 64 caracteres hexadecimais minúsculos. Query permite somente
`expected_scope_sha256` obrigatório e `limit=1..100` opcional; default 100.
O navegador usa o default, independente do tamanho da página na tabela.
A API original v0.6.11 continua com seu contrato e sem downloads.

Sessão Bearer, grant exato de leitura, Host/Origin e body vazio são verificados
antes do SQL. A conexão usa o reader SELECT-only existente. A coleta completa
mantém a cerca de escopo em cada página e consulta terminal; mudança normal
produz 409, sem retry nem arquivo parcial. Não abre o store ou escreve no banco.

Técnico e executivo compartilham **um slot por listener**, sem fila. Um segundo
download recebe 429 antes do banco. Limite 32 MiB por arquivo ZIP e os limites
herdados da coleta completa: 100 imports, 10.000 observações/avaliações, 32 MiB de
metadados técnicos. A síntese não amplia esses limites mesmo se seu resumo couber
num arquivo menor. Excesso falha sem truncar. A exportação ocupa o slot até o
envio terminar/falhar e não grava arquivos no filesystem do servidor.

Deadline cooperativo de 60s, com revalidação de sessão/grant antes/depois de cada
consulta, da síntese, da serialização e antes de devolver o arquivo. Uma consulta
em andamento conserva o timeout SQL de 30s; cancelamento no navegador não cancela
SQL imediatamente. O slot é liberado em todas as falhas tratadas.

| Resposta | Significado |
| --- | --- |
| 200 application/zip | Arquivo completo, attachment, no-store, SHA256/escopo em headers |
| 400 | Query/body/ID inválido, campo duplicado ou desconhecido |
| 401 / 403 | Sessão ausente/revogada/expirada ou assessment sem grant |
| 404 / 409 | Assessment autorizado ausente ou escopo alterado |
| 413 / 429 | Limite de bytes ou outra exportação ativa |
| 503 | Deadline, metadados inconsistentes ou backend indisponível |

Os dois botões ficam desabilitados durante a preparação. O cliente confere tipo,
nome específico do download, bytes declarados/reais, escopo e SHA256 antes de
criar o Blob temporário. Falhas recuperáveis preservam a página; negação, ausência
ou conflito limpam o relatório. Logout/expiração/reset abortam requests, revogam
URLs e impedem downloads tardios. Arquivos já salvos exigem controles locais do
operador. Hashes verificam integridade dos bytes, não autenticam autoria.

## Verificação independente de arquivo

O [verificador executivo](validation/VERIFY_OPERATOR_WEB_EXECUTIVE_v0.6.15.py)
usa somente a biblioteca padrão, sem banco, rede ou extração. Recebe um ZIP
explicitamente escolhido e as contagens esperadas do caso sintético; verifica
quatro membros, versões, hashes, contagens/grupos/referências e semântica histórica.
Falhas retornam um código fixo, sem divulgar caminhos privados. Seu código ASCII
também é exercitado por stdin com CRLF nos testes.

Esse verificador é usado pelo CI; não há roteiro de instalação manual novo
proposto hoje. As validações operacionais dos downloads técnico v0.6.13 e
executivo v0.6.15 ficam para uma etapa futura. O roteiro v0.6.13 continua fixado em
`9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871`; seu launcher rejeita Web mais nova
intencionalmente. Não misture fontes de versões diferentes ou substitua o pacote
qualificado pelo HEAD. Os roteiros/arquivos históricos desse pacote não mudaram.

## Qualificação

HTTP/eventos, PostgreSQL 16/17 e Chromium desktop/mobile qualificam dados
sintéticos e o fluxo de download; [registro CI](validation/OPERATOR_WEB_EXECUTIVE_CI_v0.6.15.md).
O relatório executivo não é renderizado como tela/PDF neste incremento. Aceites
anteriores de recovery/lifecycle/export técnico/API/Web R1 permanecem válidos em
seu escopo; nenhum deles é repetido no LAB. Não há nova dependência, migração,
conta/grant, AD, coleta, mTLS ou autenticação do portable.

[ADR 0027](ADR_0027_Operator_Web_Executive_Export_v0.6.15.md) · [Servidor](../server/README.md).
