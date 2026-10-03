# Cancã — download de relatório pela Web v0.6.13

**CANDIDATE; o R1 Web v0.6.12 permanece aprovado.** Este incremento acrescenta
somente a entrega do relatório completo ao computador do operador.

## Uso

No servidor Web da revisão v0.6.13, entre com sua conta local, consulte um
assessment autorizado e clique em **Baixar relatório completo (ZIP)**.
A consulta exibida pode ter uma avaliação por página; o ZIP inclui todas as
avaliações e as ocorrências históricas registradas sob o mesmo escopo.

| Arquivo no ZIP | Conteúdo |
| --- | --- |
| report.json | Relatório completo, avaliações, catálogo histórico e proveniência |
| report.md | Apresentação técnica em Markdown com textos persistidos inertes |
| manifest.json | ID/escopo, versões e tamanho/SHA256 dos dois relatórios |
| manifest.json.sha256 | SHA256 dos bytes do manifesto |

O formato de conteúdo continua na versão 0.6.9. A entrega Web é identificada
como 0.6.13 no manifesto. O ZIP é montado em memória no servidor, sem criar
diretório de exportação ou abrir o store. É uma ação explícita: o arquivo salvo
permanece no computador mesmo após sair da sessão; trate-o como dado do assessment.

Se o escopo mudar, a Web remove o relatório anterior e pede uma nova primeira
página. Nenhum arquivo parcial é disponibilizado. Se outra exportação estiver
em andamento, aguarde e tente novamente. Não há fila, retry automático ou job
persistente. O arquivo está limitado a 32 MiB; exportações maiores podem usar
a CLI, respeitando seus próprios limites por arquivo.

## Contrato e limites

O endpoint existe somente no listener Web:
`GET /api/v1/assessments/{id}/report/export?expected_scope_sha256={sha}`.
Aceita `limit=1..100` opcional; a Web usa 100. Grant exato de leitura é verificado
antes da conexão e em cada checkpoint. Sessão/expiração e origem/Host permanecem
nas fronteiras aprovadas. O endpoint da API v0.6.11 continua sem download.

Todas as páginas, inclusive a consulta terminal vazia, usam o escopo informado.
Há uma exportação ativa por listener, até oito workers HTTP e deadline cooperativo
de 60s. Uma consulta em andamento ainda usa o timeout SQL de 30s; abortar no
navegador não cancela imediatamente a consulta. O slot é liberado na conclusão
ou falha, inclusive durante o envio. Respostas de erro são fixas, sem DSN ou senha.

| Resposta | Significado |
| --- | --- |
| 200 application/zip | Arquivo completo, attachment, no-store, SHA256/escopo em headers |
| 400 | Query ausente, desconhecida, duplicada ou inválida |
| 401 / 403 | Sessão ausente/expirada ou sem grant para o assessment |
| 404 / 409 | Assessment autorizado ausente ou escopo alterado |
| 413 / 429 | Limite de bytes ou outra exportação ativa |
| 503 | Deadline ou backend indisponível |

O cliente limita leitura binária, confere tipo/tamanho/escopo e SHA256 antes de
iniciar o download. URLs Blob temporárias são revogadas; logout, expiração e
saída da página abortam a solicitação e impedem downloads de respostas tardias.
Hash detecta alteração; não é assinatura de autoria. Não inclui evidência bruta,
PDF ou alegação de ambiente seguro. `completed` não encerra findings históricos.

## Qualificação

HTTP e eventos do cliente cobrem denials, concorrência, limites, revogação,
respostas inválidas e races. PostgreSQL 16/17 qualifica relatório completo sob
conta SELECT-only, cerca e invariância de 14 tabelas/store. Chromium desktop/mobile
efetua downloads reais e verifica os quatro membros/hashes/contagens.

O gate manual novo é somente baixar/verificar o ZIP através do túnel Windows–Rocky
e encerrar o launcher temporário com invariantes preservadas. Os R1 anteriores
de instalação, restore, lifecycle, exportador CLI, API e Web não devem ser repetidos.
O [roteiro do novo gate](LAB_OPERATOR_WEB_EXPORT_R1_v0.6.13.md) fixa onze fontes
e hashes na revisão qualificada em CI. Não repetir os R1 anteriores.

[ADR 0025](ADR_0025_Operator_Web_Report_Export_v0.6.13.md) ·
[Servidor](../server/README.md) · [Exportador CLI](REPORT_EXPORT_v0.6.9.md).

[Qualificação CI e limites](validation/OPERATOR_WEB_EXPORT_CI_v0.6.13.md).
