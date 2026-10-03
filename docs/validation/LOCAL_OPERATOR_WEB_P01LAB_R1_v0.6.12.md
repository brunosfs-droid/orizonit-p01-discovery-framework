# Cancã — aceite das telas Web R1 v0.6.12

03/10/2026 (-03), capturas finais recebidas às 07:20. **LAB VALIDATED**,
limitado ao R1 sintético Windows–Rocky via túnel SSH/loopback. As nove capturas
iniciais e seis finais demonstram instalação, consulta, negação, logout e
encerramento com invariantes. Não reinstalar nem repetir este gate aprovado.

## Evidência observada

Nove capturas de Bruno, lidas diretamente. O Windows criou um worktree temporário
em `55980a7f2a1f824403afb3aa77fc06f13108a603`, gerou TAR com os oito arquivos,
mostrou SHA256 e envio SCP concluído. O Rocky executou o instalador com os oito
hashes qualificados e mostrou `OPERATOR WEB PACKAGE OK — persistencia aprovada
preservada`. As fontes correspondem ao pacote fixado em
`baa80267f579a93864b260f87704add3087a997f`; o commit 55980a7 altera somente o
roteiro em relação a essa revisão. Não recebemos o TAR para verificação própria.

O launcher exibiu primeiro `operator_web_lab_check_failed` após os prompts de
senha sintética. A causa não aparece no output e não será atribuída a uma senha
incorreta sem diagnóstico. Na tentativa seguinte aparece `OPERATOR WEB LAB READY`.
Esse avanço e a consulta subsequente demonstram que a primeira falha foi superada.

O túnel SSH Windows–Rocky é visível, com loopback 8878 nas duas pontas. As telas
desktop mostram login vazio, operador `OP-WEB-R1` autenticado, consulta ao
assessment sintético `P01-PG-LAB-R1`, 1 asset, 4 avaliações e 2 findings históricos.
Lifecycle completed/revisão 4 é exibido sem encerrar os findings.

Cobertura: 2 análises/2 importações, 2 fontes avaliadas/2 indexadas, 2 resultados
finding e 2 sem finding. As páginas 1 e 2 mostram resultados sem finding e a
página 4 mostra WIN-FW-001 com finding Open, recomendação e evidência registrada
`disabled_profiles: ["public"]`. Proveniência expandida apresenta analysis ID,
ordinal e referências de evidência. A página 4 desabilita Próxima página.
A página 3 e o retorno à primeira não estão individualmente capturados.

O prompt “Save your password?” pertence ao gerenciador de senhas do navegador;
não é armazenamento de senha/token pela aplicação. A senha permanece mascarada
na captura. Para esta conta sintética temporária, escolher “Not now”/“Agora não”.

| Gate | Estado observado |
| --- | --- |
| Instalação isolada / oito fontes verificadas | PACKAGE OK |
| Servidor temporário / túnel | READY / túnel visível |
| Login local / relatório desktop | Demonstrados |
| Resumo histórico / cobertura / proveniência / evidência | Demonstrados |
| Paginação | Páginas 1, 2 e 4 visíveis; Próxima desabilitada na 4 |
| Assessment OTHER negado / dados anteriores removidos | Demonstrados nas capturas finais |
| Sair / retorno ao login vazio | Demonstrados; sem relatório ou conta visível |
| Janela reduzida no LAB | Relatório legível em janela de aproximadamente 1048 px; mobile permanece qualificação CI separada |
| Encerramento / 14 tabelas invariantes / contas removidas | Dois STOP PASS, sem mutação, servidor parado e contas removidas |

## Fechamento pelas seis capturas finais

`image(20261003-100234).png` e a captura 070732 mostram `OTHER`, a mensagem
“Sua conta não possui acesso a este assessment” e ausência do relatório anterior.
A captura 070417 apresenta login vazio; a 070752 mostra “Sessão encerrada neste
navegador”, campos limpos e ausência do operador/relatório após Sair. O aceite
visual usa essas telas; não é captura independente de tokens ou requests HTTP.

A captura 070839 mostra o relatório na janela reduzida, página 1 com quatro
avaliações, linhas legíveis e proveniência/recomendações. Essa largura ainda é
desktop; não alegamos um dispositivo mobile nem teste manual de todos os breakpoints.
As páginas anteriores continuam válidas e não precisam ser recapturadas.

A captura 070908 mostra dois ciclos READY→Ctrl+C→`OPERATOR WEB LAB STOP PASS`,
cada um seguido de `INVARIANTES WEB VALIDADAS NESTA SESSAO: true`. O primeiro JSON
é legível com `tables_compared=14`, `database_mutated=false`, `store_accessed=false`,
`temporary_server_stopped=true` e `temporary_credentials_removed=true`.
O segundo repete PASS e o marcador; parte da linha fica coberta pela janela
PowerShell. A afirmação dos checks cobertos usa as asserções do launcher que
precedem a emissão de PASS, sem alegar leitura independente desses bytes.

## Limites

Os prompts finais do Rocky e PowerShell estão visíveis; o listener e o túnel
foram encerrados. Não há `unset PGPASSWORD` visível na captura final: executar
somente essa limpeza de ambiente caso ainda não tenha sido feita, sem repetir R1.

## Limites e continuidade

As 14 tabelas foram comparadas pelo launcher qualificado antes/depois de cada
ciclo. Recebemos capturas, sem acesso direto ao banco, policy temporária ou TAR;
não alegamos um snapshot independente. As duas execuções não mostram mutação
do banco nem acesso ao store. A primeira falha de startup permanece histórica,
superada pelos READY e dois encerramentos aprovados.

Os testes anteriores de API, restore, lifecycle e exportação continuam aprovados.
CI de Chromium e PostgreSQL 16/17 é uma qualificação independente já realizada
para o pacote. O PR #112 registra o aceite, porém a nova documentação aguarda CI:
os jobs de 06:58 falharam antes de qualquer etapa, sem logs recuperáveis.
O diagnóstico depende da mensagem de Annotations do GitHub Actions; nenhuma
causa financeira ou falha de código é presumida. Não repetir LAB para resolver CI.

Não qualifica HTTPS remoto do produto, AD/SSO, MFA, HA, roles de produção ou
produção. O collector portable permanece sem login Cancã; credenciais de alvos
e mTLS do Discovery Node seguem nas suas fronteiras próprias.

## Integridade das capturas

| Arquivo | SHA256 |
| --- | --- |
| image(20261003-093755).png | 57eb748472439dbf2e014ca79b6e899385a87e923846f28eb8373ed289004498 |
| image(20261003-093819).png | d51732906f3837df30c9b7f9ac8e38d14a45c000924a531a1f84555626df32a4 |
| image(20261003-094446).png | 05604f4440169bbcee7fff5f44424b013dfed553ba455098d86b4b17744daf0b |
| image(20261003-094648).png | 18fde150a7048ed4d37d557965c78c416409b39c7bc43ea16fcf8996392e998f |
| image(20261003-094733).png | c8990b7ee24d465e0cbad94c2a2326baff726c7e30939014242aec794d75f83b |
| image(20261003-094839).png | a45f0586c0b22fd3f123e9471ba94bc3ee0a96dd21d3d42c70b08f20e44b86cc |
| image(20261003-094939).png | 47604faad8bef5396ff12e1798def9d3bbfc9316ddaa8397221c3ba6eda7b188 |
| image(20261003-095049).png | cf24fad8d1f53ff1202bb6dcfb513d1cc54a2c53e8d766eadcb1c5be95112297 |
| image(20261003-095126).png | 3eeff5bb463a2dd6232998fa452d02243ee5f98849c1e8978c4b30ce919a5de5 |
| image(20261003-100234).png | 32f42ec254457ec6205b1f385f82d25d6454b116ddc3c14d21ee01e327866214 |
| Captura de tela 2026-10-03 070417.png | ff8db176a0ee705a296caee10c9f9cc5c5e5c3377781134a264549dd825ffcfc |
| Captura de tela 2026-10-03 070732.png | 46fa67eca5c3581193457789699368ec7b69715ae91fd11e659f5b66f828afa1 |
| Captura de tela 2026-10-03 070752.png | 6da6a6a4c0db5f94c9432ee61fd449f3294d46e4755ca3d49611496d849af38c |
| Captura de tela 2026-10-03 070839.png | b0cc0474bc2119d6d53dba0596f3ccaf93d2163cdefa106b1fc39a62fb0ccbfa |
| Captura de tela 2026-10-03 070908.png | 9df6ae8727b385103750cfcc70ceebb5ed8efdc0a35f979e104367f5d13a39db |

[Roteiro](../LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md) ·
[ADR 0024](../ADR_0024_Local_Operator_Web_v0.6.12.md).
