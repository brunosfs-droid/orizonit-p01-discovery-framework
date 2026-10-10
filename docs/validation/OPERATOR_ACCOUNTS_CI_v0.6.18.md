# Contas locais v0.6.18 — registro de qualificação

Data: 03/10/2026 (-03). Status: CANDIDATE operacional; código qualificado no CI.

Fonte executável: `7e769df77f7ee89b87ba299fc8a4dc36333be316`.
Tree completo: `3e1c3197cda421f83abe683901caf5461d1f1ef4`.
Base v0.6.17: `64283c544eba6695a8aec343fc2a95c5ea24e079`.
Dez runs / **24 jobs** completados com sucesso nesse head. **76 etapas críticas**
foram conferidas como executadas, com conclusão success e timestamps preenchidos.
O tree remoto é igual ao tree local completo, incluindo binários/branding.
A revisão final deste registro e de próximos passos altera apenas dois documentos;
nenhum código muda. [PR #118](https://github.com/brunosfs-droid/canca/pull/118).

## Verificação local

- Suíte Python: **496 casos**, **387 executados / 109 skips opt-in**, PASS.
- Ferramenta offline: **24 casos**, 23 executados / um skip Windows neste host
  Linux, PASS. Compilação e diff check, PASS.
- Nenhum driver novo, mudança de schema, endpoint administrativo ou alteração de
  política/sessão do listener. A revisão produz outro arquivo, sem ativação.
- Quinze arquivos preservados byte a byte da base: Auth, API, Web, Export,
  Preview, HTML/CSS/JS; Assessment Report, Report Export e Executive Report;
  guia/helper de download v0.6.13 e verificadores ZIP stdlib v0.6.13/v0.6.15.
  Os contratos Web v0.6.17 e API/Auth v0.6.11 permanecem nas versões anteriores.

## GitHub Actions da fonte

| Evento | Workflow | Run |
| --- | --- | --- |
| pull_request | Operator Accounts CI | [37163801695](https://github.com/brunosfs-droid/canca/actions/runs/37163801695) |
| pull_request | Operator Web CI | [37163801700](https://github.com/brunosfs-droid/canca/actions/runs/37163801700) |
| pull_request | PostgreSQL CI | [37163801711](https://github.com/brunosfs-droid/canca/actions/runs/37163801711) |
| pull_request | Python CI | [37163801698](https://github.com/brunosfs-droid/canca/actions/runs/37163801698) |
| pull_request | Optional Agent CI | [37163801721](https://github.com/brunosfs-droid/canca/actions/runs/37163801721) |
| push | Operator Accounts CI | [37163799395](https://github.com/brunosfs-droid/canca/actions/runs/37163799395) |
| push | PostgreSQL CI | [37163799361](https://github.com/brunosfs-droid/canca/actions/runs/37163799361) |
| push | Operator Web CI | [37163799368](https://github.com/brunosfs-droid/canca/actions/runs/37163799368) |
| push | Python CI | [37163799371](https://github.com/brunosfs-droid/canca/actions/runs/37163799371) |
| push | Optional Agent CI | [37163799398](https://github.com/brunosfs-droid/canca/actions/runs/37163799398) |

As etapas críticas incluem a suíte Python, os dois passos PostgreSQL por versão,
o fluxo Chromium, compilação e testes da nova ferramenta nas quatro combinações,
além dos contratos/interrupção/tamper e lifecycle/intervalo nativos do Agent.
Etapas condicionais da outra plataforma não contam como prova executada.

## Contas locais em Linux e Windows

A matriz dedicada `Operator Accounts CI` executa criptografia scrypt e operações
de filesystem reais, usando somente contas e senhas sintéticas. Resultados do PR:

| Runner / Python | Casos | Executados | Skips previstos | Resultado |
| --- | --- | --- | --- | --- |
| ubuntu-latest / 3.10 | 24 | 23 | 1 Windows | PASS |
| ubuntu-latest / 3.12 | 24 | 23 | 1 Windows | PASS |
| windows-latest / 3.12 | 24 | 21 | 3 POSIX | PASS |
| windows-latest / 3.13 | 24 | 21 | 3 POSIX | PASS |

Os runs push também passaram nas quatro combinações. Em Windows os testes de
symlinks de arquivo/diretório e UNC foram realmente executados. A criação de
conta e rotação usam o scrypt existente; uma instância nova de LocalAuth aceita
a nova senha e aplica os grants, enquanto outra já iniciada conserva a política
e as sessões anteriores. Desabilitar um operador no arquivo candidato também
não altera a instância em execução. A aplicação exige reinício controlado futuro.

Os 24 casos cobrem:

- inspeção e CLI sem salt/hash de senha; criação e prompts ocultos; substituição
  integral ou limpeza explícita de grants, isolamento entre operadores,
  habilitação/desabilitação e rotação com autenticação real;
- IDs duplicados/inválidos, grants repetidos, limite de 128 contas/grants,
  alterações sem efeito, JSON duplicado/inválido e política acima de 64 KiB;
- hash de origem obrigatório, conflito antes dos prompts, mudança da origem
  durante a senha e substituição por outro inode com os mesmos bytes;
- senha curta/divergente, stdin não interativo, EOF/interrupção, argumentos
  secretos/flags desconhecidas/abreviações e erros fixos sem eco de dados;
- origem privada, hardlinks/symlinks/UNC, diretórios e FIFO em POSIX,
  permissões do diretório de destino alteradas durante o prompt;
- destino existente/igual à origem, criação concorrente do destino, falhas de
  fsync/link, limpeza do staging pertencente à operação e revisão acima do limite;
- saída abrupta do subprocesso antes da publicação: arquivo privado de staging
  permanece sem ser aplicado; outra operação não o promove nem apaga;
- falha de fsync do diretório depois da publicação em POSIX: erro fixo, origem
  intacta e candidato completo/privado que pode permanecer no destino.

Não há sobrescrita do arquivo vigente nem reload automático. O sucesso informa
`restart_required=true` e `live_sessions_updated=false`. Os registros de senha
continuam apenas nos arquivos privados; a saída descreve a alteração e SHA256
da política completa. Esse SHA não é um hash individual de senha.

## Compatibilidade da base

- Python CI: **496 casos / 109 skips**, PASS; mesma contagem local. O
  `backup_restore_failed` emitido pelo teste negativo de guardrail é esperado.
- PostgreSQL **16.15 / 17.11**: **187 casos por versão, sem skips**, PASS.
  Relatórios, autorização e SELECT-only continuam exercitados. Backup/restore
  lógico passou nas duas versões, com 14 tabelas / 20 arquivos e replay.
- Node: **20 grupos de comportamento**, PASS. Chromium real a **1280 / 390 px**:
  grants isolados, resumo/hash, zero imports, 12 grupos em páginas 10+2,
  logout/reload e ambos os downloads, PASS.
- Optional Agent: quatro combinações Linux/Windows e Python, PASS. Etapas
  nativas systemd/SCM e intervalos/espera interrompida executadas nas respectivas
  plataformas; contratos, processo interrompido e adulteração offline preservados.

## Artefatos Web conferidos

Artifact **11287979903**, `operator-web-synthetic-screens`, do run PR Web
37163801700; fonte confirmada no head acima, não expirado no download,
**1132523 bytes**, SHA256 externo
`3039926c5c7466c962f79016079c32dff4b45c47006d6e5ac1ec4303d0423415`.
Retenção de sete dias; fontes, runs e hashes permanecem registrados em Git.

Inventário de **14 membros fixos**, sem duplicatas ou nomes estrangeiros,
conferido antes da leitura. Até 2 MiB por membro e 20 MiB no total; nenhuma
extração genérica. Todos os 14 payloads têm os mesmos hashes da fixture v0.6.17,
incluindo os oito PNG. Os PNG do resumo mantêm 1280×3050 e 390×4627; a inspeção
visual registrada na v0.6.17 corresponde a esses mesmos bytes.

| Payloads em 1280 / 390 px | SHA256 | Conferência |
| --- | --- | --- |
| preview JSON | `316b4b43ae7fc0cbfc5d291b6d8fd8ac2d9f988dee27dd68335a281eb5677535` | 3685 bytes, projeção da síntese completa PASS |
| report ZIP | `8b828ed3efb3b7714efe4ce96b8158ec753dfc400a4d71c9a848b7d391418bb9` | FILE PASS v0.6.13 |
| executive ZIP | `c39b02f37f3816a731179fea1b09a800a27ad649a4d97193bdc3944fcd795cf3` | EXECUTIVE FILE PASS v0.6.15 |

Os quatro ZIP foram conferidos pelos verificadores stdlib preservados: quatro
membros internos, quatro avaliações, dois findings históricos e dois grupos no
executivo, terminal vazia verificada. Os dois JSON foram comparados à projeção
por campos explícitos da síntese completa; referências de ocorrências, evidência
bruta/extraída e risco atual continuam ausentes ou false conforme o contrato.
A igualdade de bytes comprova esta fixture/formato; outros dados e timestamps
podem mudar hashes. Hashes de conteúdo não comprovam autoria.

## Limites e validações adiadas

Nenhuma ação no LAB solicitada hoje. Nenhuma conta real, política implantada,
serviço, banco, store ou alvo foi alterado. Os R1 e soaks aceitos não precisam ser
repetidos. Gates de download e telas posteriores permanecem adiados; este CI
não os declara aprovados.

O controle por hash/metadados da origem detecta mudanças observadas antes da
publicação; é uma cerca consultiva, sem lock global nem defesa contra o dono
hostil do filesystem. A publicação exige hardlinks no mesmo diretório privado.
Interrupção abrupta pode deixar staging privado; falha após publicação pode deixar
um candidato completo mesmo com exit 2. Nenhum desses arquivos é aplicado sozinho.

POSIX exige origem e diretório de saída privados, com 0600/0700 recomendados. Windows
requer ACL restritiva na implantação futura. A matriz nativa comprova as operações
no filesystem dos runners; não qualifica ACLs de produção, todos os filesystems,
troca operacional do arquivo nem revogação em um servidor implantado.

Collector portable permanece sem login Cancã; credenciais de alvo e mTLS de Node
seguem separados. AD/SSO, tenancy, RBAC ampliado, TLS/roles de produção,
inventário/mapper e quotas comerciais continuam decisões/gates próprios.
Não há dependência de teste pelo mantenedor para integrar este incremento.

[Contrato](../OPERATOR_ACCOUNTS_v0.6.18.md) ·
[ADR 0030](../ADR_0030_Offline_Operator_Accounts_v0.6.18.md) ·
[Compatibilidade Web anterior](OPERATOR_WEB_PREVIEW_CI_v0.6.17.md).
