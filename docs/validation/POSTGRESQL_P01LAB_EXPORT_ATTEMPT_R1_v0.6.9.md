# P01 — tentativa de exportação R1 v0.6.9

02/10/2026 (-03). **Registro histórico de tentativas bloqueadas.** O ensaio
funcional posterior foi aprovado; [aceite atual](POSTGRESQL_P01LAB_EXPORT_R1_v0.6.9.md).
Na tentativa descrita abaixo o gate estava CANDIDATE. Quatro capturas
recebidas foram inspecionadas, sem acesso ao host ou recebimento do TAR real.

| Captura | Evidência visível | Conclusão |
| --- | --- | --- |
| 235251 | Windows fetch/archive da revisão a70af4, hash e scp; Rocky AssertionError `inventario do tar diferente` | Validação do pacote interrompida antes de escrever o exportador |
| 235559 | Bloco de exportação sob `P01_EXPORT_READY` | Comandos exibidos, sem resultado da consulta |
| 235634 | Código de verificação de hashes, contagens e permissões | Não demonstra execução nem PASS |
| 235648 | `PARAR: execute a instalacao validada da etapa 1 primeiro.` | Exportação bloqueada pelo gate da instalação |

O roteiro fornecido exigia exatamente uma entrada no TAR. Um `git archive` do
caminho `persistence/P01_Report_Export.py` inclui também a entrada da pasta
`persistence/`. Essa causa foi reproduzida com Git em repositório temporário,
sem consulta ao banco. O inventário do TAR recebido não foi enviado, portanto a
conclusão não atesta seus bytes exatos. O roteiro corrigido valida o inventário
e o hash do módulo no host antes de liberá-lo.

O novo bloco permite um arquivo regular no caminho exato e até uma entrada de
diretório no caminho esperado, que não é extraída. Rejeita links, caminhos
extras, duplicatas, conteúdo diferente da revisão qualificada e tamanhos fora
do limite. Instala apenas o arquivo novo ou aceita repetição idêntica; não
sobrescreve exportador diferente. Preserva o SHA do engine original CRLF.

O módulo a enviar é o exportador após PR #106: merge
d1b32cf6d6185e87fc4a08abb57654c29d8e8c4b. SHA256 LF
`d2ec90a2624d9c374a53a76e9307417eddf8c89b77d9c3dff06983b319d07bd8`, CRLF
`d409898b63be0477d08319a3a13f090d79bf05cdcbdc3ff3699e49128cf1e830`.
As duas formas são produzidas por `git archive` com atributos de EOL e
verificadas no teste; nenhuma normalização é feita no deployment do LAB.

O teste de regressão executa o bloco Python do roteiro, com somente os caminhos
redirecionados para fixtures temporárias. Valida Git real LF/CRLF, pacote sem
entrada de pasta, repetição idêntica, preservação de arquivo diferente, engine
divergente, aliases, inventários inválidos e o gate Bash sem chamar Python
quando readiness é false. Sem teste destrutivo, migração, credenciais reais ou
conexão PostgreSQL. O preflight anterior usou um TAR sintético com apenas o
arquivo, por isso não detectou a entrada de diretório gerada pelo Git.

Próximo teste no host: [roteiro corrigido](../LAB_POSTGRESQL_EXPORT_R1_v0.6.9.md).
Refazer somente envio/instalação e exportações de páginas 1/100, na mesma sessão.
Não repetir restore, lifecycle, AUTH/FULL/POST ou serviços. A falha de instalação
não invalida os aceites anteriores e não prova falha da consulta ao banco.
Aceite requer `EXPORTADOR OK`, dois JSONs `exported`, `POSTGRESQL LAB EXPORT PASS`
e `Exportacao validada nesta sessao: true`, além da revisão de apresentação.

## Capturas adicionais 003724/003738/003753

Recebidas em 02/10/2026 (-03). A captura 003724 mostra novo envio de um TAR
da revisão a70af461c9d35dd97aaa6810995c920e4d77df22, anterior ao escape de URLs
do PR #106. A captura 003753 mostra o mesmo SHA256 do TAR no Rocky e a execução
do bloco antigo `assert len(members) == 1`; ele termina em `inventario do tar
diferente` e `instalacao nao validada`. A captura 003738 contém comandos do
bloco de exportação; 003724 termina com `execute a instalacao validada da etapa
1 primeiro`. Não há JSON `exported` nem PASS demonstrado.

Gate permanece CANDIDATE. A correção de inventário foi integrada pela PR #107,
merge 6e040af501470d80d76ede889f29a00ade4167f1. Usar as etapas 1 e 2 do
roteiro atual: o TAR deve partir de d1b32cf6d6185e87fc4a08abb57654c29d8e8c4b,
e o bloco Rocky aceita somente o arquivo esperado mais a pasta opcional.
Preservar o deployment e o engine original; não repetir restore/lifecycle.
