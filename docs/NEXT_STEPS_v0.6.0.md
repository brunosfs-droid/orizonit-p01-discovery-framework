# P01 — Próximos passos da Product Alpha

Atualizado em 04/10/2026 (-03), com desenvolvimento independente do LAB.

## Preciso testar alguma coisa agora?

**Não há validação solicitada hoje.** O mantenedor adiou os testes de LAB em
03/10. O novo download Web v0.6.13 permanece CANDIDATE, com seu pacote qualificado
fixado em `9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871`, com os onze arquivos
preservados nesse pin.
O [relatório executivo v0.6.14](EXECUTIVE_REPORT_v0.6.14.md) avança como CLI
somente leitura, com testes sintéticos/PostgreSQL no CI e qualificação operacional
futura. Não depende de acesso ao LAB ou de execução pelo mantenedor para desenvolver.

O [download executivo Web v0.6.15](OPERATOR_WEB_EXECUTIVE_v0.6.15.md) integra essa
síntese ao listener novo, com um slot compartilhado entre os dois tipos de
download. As fontes Web em desenvolvimento evoluem; os pacotes históricos
permanecem preservados nos seus pins, sem misturar HEAD no roteiro v0.6.13.
Testes sintéticos/PostgreSQL/Chromium seguem no CI; nenhum novo passo manual hoje.

v0.6.16 acrescenta [seleção dos assessments permitidos](OPERATOR_ASSESSMENT_SELECTION_v0.6.16.md)
na Web. A lista lê apenas os grants da sessão e não depende de PostgreSQL;
selecionar preenche o formulário, com consulta explícita e autorização preservada.
Não cria assessments nem qualifica downloads no LAB. Nenhuma nova ação manual hoje.
Fonte `0cbba0c2742b4c10d59c993e65680c208de98c48` qualificada em oito runs / 16 jobs,
incluindo 186 casos em cada PostgreSQL 16/17 e Chromium desktop/mobile;
[registro e limites](validation/OPERATOR_ASSESSMENT_SELECTION_CI_v0.6.16.md).

v0.6.17 acrescenta [resumo executivo na própria Web](OPERATOR_WEB_PREVIEW_v0.6.17.md):
cobertura completa do escopo exibido, severidades históricas e recomendações em
páginas de dez grupos, com proveniência. Usa a síntese executiva v0.6.14 e um slot
compartilhado com os dois downloads. Nenhum formato ZIP ou guia histórico muda.
CI sintético/PostgreSQL/Chromium segue independente; nenhum novo passo manual hoje.
Fonte `d2947213df84cdb9896ee193c421970dec39a08f` qualificada em oito runs / 16 jobs:
187 casos em cada PostgreSQL 16/17, Chromium a 1280/390 px e ZIPs preservados.
[Registro de qualificação](validation/OPERATOR_WEB_PREVIEW_CI_v0.6.17.md).

v0.6.18 acrescenta [administração offline das contas locais](OPERATOR_ACCOUNTS_v0.6.18.md):
inspeção redigida e geração de arquivo privado novo para adicionar operadores,
substituir grants, habilitar/desabilitar ou trocar senha. Exige o hash da origem,
preserva os demais operadores e não altera políticas/sessões em execução.
CI Linux/Windows usa apenas políticas sintéticas. Web v0.6.17 e API v0.6.11
permanecem compatíveis; nenhuma conta real ou serviço do LAB é alterado hoje.
Fonte `7e769df77f7ee89b87ba299fc8a4dc36333be316` qualificada em dez runs / 24 jobs:
24 casos nativos em Linux/Windows, suíte Python com 496 casos / 109 skips,
187 casos em cada PostgreSQL 16/17 e artefatos Web byte a byte preservados.
[Registro de qualificação](validation/OPERATOR_ACCOUNTS_CI_v0.6.18.md).

v0.6.19 acrescenta [auditoria privada opcional do servidor](OPERATOR_SERVER_AUDIT_v0.6.19.md):
início/fim de requests, operações fixas e IDs autorizados, sem copiar senhas,
tokens, URLs ou relatórios. Arquivo novo por listener com orçamento de 8 MiB;
falha de admissão da auditoria nega novo trabalho antes de autenticação/SQL.
Default desativado; CI HTTP, filesystem Linux/Windows, reader PostgreSQL e
Chromium usam somente dados sintéticos. Nenhum novo passo manual ou alteração
de conta, serviço ou configuração do LAB solicitado em 04/10.
Fonte `2a7fa52943903b12eda1ba7c25671a21cbf11482` qualificada em dez runs / 24 jobs:
28 casos de auditoria na matriz Linux/Windows, suíte Python com 525 casos / 111 skips,
188 casos em cada PostgreSQL 16/17 e Chromium com fechamento privado verificado.
Os 14 payloads Web permanecem byte a byte iguais aos da v0.6.18.
[Registro de qualificação](validation/OPERATOR_SERVER_AUDIT_CI_v0.6.19.md).

v0.6.20 acrescenta [revisão offline da auditoria](OPERATOR_AUDIT_CHECK_v0.6.20.md):
leitura privada, estados encerrado/prefixo aberto/cauda parcial e contagens fixas
sem IDs privados. Não repara registros nem declara um prefixo como encerramento.
CLI e fixtures Linux/Windows, HTTP, PostgreSQL e Chromium seguem independentes;
nenhum novo passo manual ou alteração no LAB solicitado hoje.
Fonte `43b7a510e92f3d01b993a1847cd1695879ef85bf` qualificada em dez runs / 24 jobs:
30 casos de revisão na matriz Linux/Windows, suíte Python 555 casos / 112 skips,
188 casos por PostgreSQL 16/17 e Chromium com estrutura encerrada verificada.
Quatro ZIP e dois JSON de relatórios preservados byte a byte; uma diferença
pontual na captura desktop de seleção está documentada no registro abaixo.
[Registro de qualificação](validation/OPERATOR_AUDIT_CHECK_CI_v0.6.20.md).

O exportador funcional está **LAB VALIDATED no R1 sintético Rocky**. As cinco
capturas 014007/014025/014138/014149/014247 demonstram instalação corrigida,
duas respostas `exported`, verificação PASS e exportação da sessão `true`.
[Aceite e limites](validation/POSTGRESQL_P01LAB_EXPORT_R1_v0.6.9.md).
Não repetir instalação/exportação, restore, lifecycle ou serviços. A apresentação
técnica foi aceita por conteúdo/parsing GFM dos dois anexos idênticos. Preservar
os dois diretórios gerados. Tentativas bloqueadas anteriores permanecem históricas.

**O desenvolvimento de código/CI segue independentemente do LAB PostgreSQL.** R1 curto e soak estendido
do scheduler estão aprovados em Windows e Rocky no escopo offline demonstrado.
Não é preciso repetir os testes ou reinstalar serviços removidos pelo helper.

O soak estendido usou 10 ticks com intervalo real de 60s, ciclos de 540,911s e
540,310s, auditorias PASS e exit 0 nos dois hosts. Intenções interrompidas e fixtures
ficam preservadas; o restart em revisão com zero chamadas é esperado.
[Aceite e limites](validation/SCHEDULER_P01LAB_EXTENDED_v0.5f.3.md).

Multi-day e qualificação do principal para AUTH/FULL/POST continuam independentes;
o soak offline de cerca de 9 minutos não os comprova. Não há execução live proposta
como dependência deste incremento.

## PostgreSQL e desenvolvimento

v0.6.0 entregou a fundação do índice; v0.6.1 integrou ingestão/índice de forma opt-in
e reconciliação explícita; v0.6.2 adiciona ciclo de vida administrativo do assessment
com revisão, idempotência e histórico transacional. v0.6.3 entrega identidade
persistente de assets por assessment, com origem verificável e revisão de
ambiguidades. v0.6.4 adiciona findings de duas regras WinRM com origem, cobertura explícita e
ocorrências imutáveis, sem fechar findings de runs anteriores. v0.6.5 consolida consultas de lifecycle, identidade, cobertura e ocorrências
históricas, com paginação consistente. v0.6.6 qualifica a recuperação de banco/store
em CI descartável, com comparação integral, hashes e replay. v0.6.7 adiciona um helper somente leitura para verificar a recuperação na fixture R1.
O R1 básico e a recuperação do par sintético estão **LAB VALIDATED** em PostgreSQL 16.15.
v0.6.8 está LAB VALIDATED para lifecycle/paginação na base recuperada.
v0.6.9 adiciona exportação consolidada somente leitura em JSON/Markdown com hashes.
TLS/roles completos e restante da Product Alpha continuam CANDIDATE.

O roteiro R1 abaixo orienta a instalação em base/store isolados; não altere o store atual.
Nenhuma migração é automática. A recuperação sintética em CI está implementada;
o harness destrutivo de CI não deve ser executado no LAB. Recuperação de produção,
contas e TLS remoto requerem qualificação própria. Resolução manual e
continuidade de IDs entre assessments terão decisões próprias.

[Findings v0.6.4](FINDINGS_v0.6.4.md) ·
[Assets v0.6.3](ASSET_REGISTRY_v0.6.3.md) ·
[Lifecycle v0.6.2](ASSESSMENT_LIFECYCLE_v0.6.2.md) ·
[Integração v0.6.1](INGESTION_INDEX_v0.6.1.md) ·
[R1 curto](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md)

## R1 PostgreSQL básico aprovado

As 18 capturas demonstram PostgreSQL 16.15 active/running em loopback, 64MB shared_buffers,
10 conexões e cerca de 646MiB disponíveis na observação após start. HBA foi corrigido;
migrate/replay, fixture, index/assets/findings e relatório passaram. Reader consultou
as 4 avaliações e foi corretamente impedido de UPDATE. Não é necessário repetir as etapas 1–6.
[Aceite e limites](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md).

A API/store /root/p01/store-v05e-r1 não integra a fixture de recuperação. Dados aprovados:
base canca_p01_lab_r1, fixture /var/lib/canca/postgres-lab/P01-PG-R1-06230404e329/server-store.

Recuperação R1 aprovada por sete capturas: destino canca_p01_restore_r1, 14 tabelas/20 arquivos,
revalidação de fontes e replay sem mudança do snapshot. [Aceite e limites](validation/POSTGRESQL_P01LAB_RECOVERY_R1_v0.6.7.md).
Não repetir instalação, dump ou restore.

Lifecycle/paginação aprovado nas quatro capturas seguintes: inspect PASS;
primeiro exercise registered/0→completed/4, quatro transições e quatro rejeições
de cursor; replay sem novas transições/eventos. Dois exit 0, quatro replays e
três conflitos esperados; 12 tabelas invariantes/store/fontes preservados.
[Aceite e limites](validation/POSTGRESQL_P01LAB_LIFECYCLE_R1_v0.6.8.md).
Não repetir esse gate nem restore. Completed não fecha os findings históricos.

Exportação v0.6.9 implementa JSON completo, Markdown e manifesto/SHA256 em diretório
privado novo. Só SELECT via relatório canônico, todas as páginas e verificação
terminal sob a mesma cerca; mudança de escopo interrompe antes de gerar arquivos.
[Guia e limites](REPORT_EXPORT_v0.6.9.md). Qualificação CI é independente do host LAB;
exportação funcional no R1 Rocky passou nas cinco capturas posteriores; conteúdo
e estrutura GFM de `report.md`/`report1.md` idênticos foram aceitos. Renderização
gráfica específica e PDF/impressão não foram qualificados.
PR #106 integrado (d1b32cf6d6185e87fc4a08abb57654c29d8e8c4b): texto persistido
inclui escape de URLs simples para evitar autolinks no Markdown. Não há mudança
no banco, nas regras ou no formato JSON. O roteiro novo usa essa revisão qualificada.
v0.6.10 adiciona uma política opt-in de node/assessment ao mTLS da ingestão,
com grants independentes para envio/consulta e negação antes do importer/index.
O principal continua sendo o Discovery Node; autenticação de operadores locais
foi implementada separadamente na v0.6.11. Tenancy e RBAC ampliado seguem pendentes.
[Guia e limites](NODE_AUTHORIZATION_v0.6.10.md). Roles/TLS continuam gates próprios.

[Relatório v0.6.5](ASSESSMENT_REPORT_v0.6.5.md) · [Backup/restore CI v0.6.6](BACKUP_RESTORE_v0.6.6.md).

## Operadores do servidor v0.6.11 — R1 aprovado

Bruno confirmou login local no servidor inicialmente, com integração AD opcional
futura. O collector portable executa sem login Cancã; suas credenciais de alvos
e o mTLS de upload permanecem nas fronteiras atuais. A API de operadores é
separada e somente leitura por assessment, sem telas Web neste incremento.
[Guia e limites](../server/README.md) · [R1 curto](LAB_LOCAL_OPERATOR_R1_v0.6.11.md).
O R1 usa servidor temporário em 127.0.0.1 e somente SELECT na base recuperada;
não repetir restore/lifecycle/exportação nem instalar serviço ou liberar firewall.
As duas capturas de 03/10 mostram instalação isolada e `LOCAL OPERATOR LAB PASS`.
[Aceite e limites](validation/LOCAL_OPERATOR_P01LAB_R1_v0.6.11.md). Não repetir este R1.

## Primeiras telas Web v0.6.12 — R1 aprovado

Login local, relatório histórico por assessment e logout usam o backend aprovado,
sem alterar a persistência. Sessão somente em memória; consultas paginadas com cerca.
[ADR 0024](ADR_0024_Local_Operator_Web_v0.6.12.md) ·
[Roteiro de navegador](LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md).
Quinze capturas de 03/10 demonstram instalação, túnel, login, resumo/cobertura,
proveniência/evidência, páginas 1/2/4, negação OTHER, logout/login vazio e janela
reduzida. Dois STOP PASS comprovam as asserções do launcher: 14 tabelas preservadas,
sem mutação no banco/acesso ao store e com servidor/contas temporários removidos.
[Aceite e limites](validation/LOCAL_OPERATOR_WEB_P01LAB_R1_v0.6.12.md).
Não repetir instalação nem Web, backend, restore, lifecycle ou exportação.

## Actions recuperado; próxima entrega v0.6.13

Em 03/10 Bruno resolveu o bloqueio e o repositório está público. Oito runs, com
16 jobs, passaram no attempt 2 do head 64e0fa65547840a407a9c9588524898a8a7f8678.
PR #112 integrado em dcfb654507428f2a4287caed18e4a6b7d5431b8f; o aceite Web R1
está no main. Nenhum R1 aprovado deve ser repetido para essa recuperação de CI.

v0.6.13 acrescenta download completo de relatório pela Web: ZIP em memória com
JSON/Markdown, manifesto/SHA256 e cerca ligada ao relatório exibido. Mantém
somente SELECT e sessões/grants; não altera collector, store ou banco.
[Guia e limites](OPERATOR_WEB_EXPORT_v0.6.13.md). O novo gate de LAB será somente
baixar/verificar o arquivo e encerrar o servidor temporário; o roteiro ficará
fixado na revisão qualificada em CI. [Novo gate R1](LAB_OPERATOR_WEB_EXPORT_R1_v0.6.13.md):
pacote isolado, uma consulta/download, FILE PASS e STOP PASS. Oito runs/16 jobs
passaram no código 9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871;
[qualificação e limites](validation/OPERATOR_WEB_EXPORT_CI_v0.6.13.md).
Mapa/topologia permanecem após 1.0.
