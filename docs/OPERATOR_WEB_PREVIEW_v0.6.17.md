# Resumo executivo na Web v0.6.17

Status: CANDIDATE operacional. Desenvolvimento e CI independentes dos testes
manuais adiados pelo mantenedor em 03/10/2026 (-03). Nenhuma ação no LAB hoje.
[ADR 0029](ADR_0029_Operator_Executive_Preview_v0.6.17.md) ·
[Registro CI](validation/OPERATOR_WEB_PREVIEW_CI_v0.6.17.md).

## Uso e significado

Consulte um assessment permitido e clique em **Ver resumo executivo**. O resumo
usa todos os imports e avaliações persistidos do escopo exibido, mesmo quando a
tabela técnica mostra uma única avaliação. Não há carregamento automático na
entrada, na seleção de um assessment ou ao paginar a tabela técnica.

O painel apresenta contagens de avaliações, análises/imports, fontes indexadas/
avaliadas, pendências de projeção, decisões de identidade, severidades registradas
e recomendações dos catálogos históricos. Os cinco resultados de avaliação
permanecem distintos: finding, sem finding, evidência insuficiente, não aplicável
e não suportado. Ausência de imports ou findings não comprova ambiente seguro.
Uma análise posterior sem finding não encerra ocorrências anteriores; o lifecycle
completed continua administrativo. Não há score de risco atual ou remediação.

As recomendações usam a mesma síntese qualificada v0.6.14 do download executivo.
Cada grupo preserva regra/versão, policy e hashes do catálogo/engine de origem.
As contagens de assets vinculados são por grupo; somá-las não produz um total de
assets únicos. Abra **Regra e proveniência** para consultar as referências do
grupo. Este painel exclui IDs/referências das ocorrências, bundles, caminhos e
evidência bruta/extraída; o download executivo mantém suas referências completas.

**Próximas recomendações** mostra os próximos dez grupos; **Primeiras
recomendações** volta ao início. Essa paginação é independente da tabela técnica,
mas cada pedido confere novamente todo o histórico sob o mesmo escopo. Não há
cache, retry ou atualização implícita para o escopo mais recente.
**Ocultar resumo** limpa seus dados da memória, preservando a página técnica.
Uma nova consulta ou seleção de outro assessment limpa o resumo. Editar o ID
manualmente mantém o assessment/escopo do relatório já exibido até consultar.

## Contrato do listener

Somente a Web oferece:

```text
GET /api/v1/assessments/{id}/report/executive?expected_scope_sha256={sha}&group_offset=0
```

Bearer válido, grant exato, Host/origem e body vazio são obrigatórios. O SHA do
relatório exibido tem 64 caracteres hexadecimais minúsculos e é obrigatório.
`group_offset` é opcional (default 0), decimal canônico, múltiplo de dez entre 0 e
200. Offsets positivos fora dos grupos existentes falham; zero aceita histórico
vazio. Query duplicada/desconhecida, inclusive `limit`, é rejeitada. O servidor
usa páginas canônicas de 100 avaliações, com a consulta terminal vazia verificada.

JSON possui `preview_version=0.6.17`, `executive_version=0.6.14`, assessment/escopo,
lifecycle, coverage, identity, contagens de findings/severidades, até dez grupos,
pagination, consistency e semantics. Apenas campos explícitos da síntese entram
na projeção. `semantics.occurrence_references_included=false`; as demais flags
preservam evidência excluída, fontes não revalidadas e risco atual não calculado.

| Resposta | Significado |
| --- | --- |
| 200 | `application/json; charset=utf-8`, no-store, Content-Length, `X-Canca-Report-Scope-SHA256` e `X-Canca-Executive-Preview-SHA256` |
| 400 | Query/body/ID/offset inválido ou continuação além dos grupos existentes |
| 401 / 403 | Sessão ausente/revogada/expirada ou assessment sem grant; negação antes de SQL |
| 404 / 409 | Assessment autorizado ausente ou escopo alterado; sem resumo parcial |
| 413 | Limite de metadados/síntese herdado ou JSON do painel acima de 1 MiB |
| 429 | Outro resumo ou download ocupa o slot do listener |
| 503 | Deadline, metadados inconsistentes ou backend indisponível; código fixo |

Não há migração, SQL de escrita, abertura do store ou acesso a alvos. O reader
SELECT-only permanece obrigatório. A API standalone v0.6.11 não oferece essa rota.
A cerca confere alterações normais em todas as páginas; não é snapshot durável,
assinatura de autoria ou proteção contra alteração por DBA.

## Limites e sessão

Resumo e ambos os ZIP compartilham **um slot por listener**, sem fila. A coleta
mantém os limites existentes de 100 imports, 10.000 observações/avaliações e
32 MiB de metadados técnicos, mesmo se o painel resultante for pequeno. Até
200 grupos decorrem dos imports e das duas regras atuais. JSON do painel é
limitado a 1 MiB; nenhum resultado é truncado silenciosamente.

Deadline cooperativo de 60s com checagens de sessão/grant antes/depois das
consultas, síntese, serialização e antes do envio. A conexão SQL conserva seu
timeout de 30s por statement; abortar o navegador não cancela SQL imediatamente.
O slot permanece ocupado durante o envio e é liberado ao sair, inclusive em falha.
Cada página de recomendações repete a coleta completa; esse custo é explícito.

O navegador limita o stream a 1 MiB, confere MIME, comprimentos declarado/real,
escopo e SHA256 antes de parsear UTF-8/JSON; depois verifica versões, contadores,
textos, grupos, proveniência, paginação e semântica histórica. Renderização é
somente texto. Hashes conferem integridade dos bytes recebidos, não autoria.

Durante consulta/resumo/download, os demais controles ficam indisponíveis;
**Sair** permanece utilizável. Logout, expiração absoluta da sessão e restauração
da página abortam pedidos, limpam dados e descartam respostas antigas, inclusive
após nova entrada. Não há tokens/dados em cookies, localStorage ou sessionStorage.
Falha recuperável limpa o resumo e mantém a página técnica; 403/404/409 limpam
ambos; 401 encerra a sessão local. Bytes já enviados não podem ser retirados por
uma revogação posterior à última checagem, como nas consultas existentes.

## Compatibilidade e qualificação

| Interface/conteúdo | Versão preservada |
| --- | --- |
| Diretório dos grants locais da sessão | 0.6.16 |
| Relatório canônico / exportação técnica | 0.6.5 / 0.6.9 |
| Entrega ZIP técnico | 0.6.13 |
| Síntese executiva / entrega ZIP executivo | 0.6.14 / 0.6.15 |
| API e política local de operadores | 0.6.11 |

Testes sintéticos/HTTP cobrem histórico completo, whitelist, alinhamento/limites,
recolhimento da continuação, slot compartilhado, deadline e revogação. PostgreSQL
16/17 real confere igualdade com a síntese completa via reader e invariância das
14 tabelas/store. Node e Chromium desktop/mobile verificam resumo vazio, 12
grupos, texto/proveniência, navegação independente, hash, limpeza e os dois ZIP.

Qualificação de CI não aprova os gates manuais adiados de download/relatórios.
Os guias/helpers/verificadores históricos mantêm seus pins e formatos. Não há
instalação no LAB, mudança em serviços/firewall, AD/SSO, quotas ou collector login.
