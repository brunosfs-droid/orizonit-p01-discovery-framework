# Cancã — validação parcial das telas Web R1 v0.6.12

03/10/2026 (-03), capturas recebidas até 06:53. **R1 EM VALIDAÇÃO**.
Instalação, login e relatório desktop demonstrados; aceite completo depende das
etapas finais abaixo. Não reinstalar nem repetir os gates já aprovados.

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
| Assessment OTHER negado / dados anteriores removidos | Captura pendente |
| Sair / recarregar sem conta ou relatório | Captura pendente |
| Janela estreita / rolagem própria da tabela no LAB | Pendente; Chromium CI já cobre cenário sintético separado |
| Encerramento / 14 tabelas invariantes / contas removidas | STOP PASS pendente |

## Retomar somente o que falta

Com o launcher e o túnel ainda abertos, usar a sessão existente. Se ela expirou,
entrar novamente com `reader-web` e a senha sintética da execução atual.

1. Consultar `OTHER`; capturar acesso negado e ausência do relatório anterior.
2. Consultar novamente `P01-PG-LAB-R1`, reduzir a largura da janela e conferir
   os formulários e a rolagem horizontal dentro da tabela. Depois clicar Sair
   e recarregar; capturar o login sem conta/relatório visível.
3. Ctrl+C na janela Rocky. Capturar `OPERATOR WEB LAB STOP PASS`, 14 tabelas,
   `database_mutated=false`, `store_accessed=false`, servidor parado e contas
   removidas, seguido de `INVARIANTES WEB VALIDADAS NESTA SESSAO: true`.
   Executar `unset PGPASSWORD` no Rocky se ainda não foi executado.
4. Ctrl+C na janela PowerShell do túnel.

Se o launcher já foi encerrado, enviar primeiro a saída final existente. Não
reiniciar, reinstalar ou alterar banco/grants para substituir uma evidência ausente.

## Limites

O resumo do relatório e READY não comprovam a comparação final de 14 tabelas,
remoção de contas ou parada do servidor. Sem STOP PASS o R1 completo continua
pendente. Os testes anteriores de API, restore, lifecycle e exportação continuam
aprovados e não precisam ser repetidos. CI de Chromium e PostgreSQL 16/17 permanece
uma qualificação independente, sem substituir esses passos do host.

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

[Roteiro](../LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md) ·
[ADR 0024](../ADR_0024_Local_Operator_Web_v0.6.12.md).
