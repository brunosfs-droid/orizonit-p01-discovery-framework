# Auditoria de operadores v0.6.19 — registro de qualificação

Data: 04/10/2026 (-03). Status: CANDIDATE operacional; código qualificado no CI.

Fonte executável: `2a7fa52943903b12eda1ba7c25671a21cbf11482`.
Tree completo: `9ff1035fc637a726ee475db477ca046b09abb3d1`.
Base v0.6.18: `b59e26a3583263f7f0e6032bca31e09e2e3eef4e`.
Dez runs / **24 jobs** completados com sucesso nesse head. **98 etapas críticas**
foram conferidas como executadas, com conclusão success e timestamps preenchidos.
O tree remoto é igual ao tree local completo, incluindo binários/branding.
A revisão final deste registro e de próximos passos altera apenas dois documentos;
nenhum código muda. [PR #119](https://github.com/brunosfs-droid/canca/pull/119).

## Verificação local

- Suíte Python: **525 casos**, **414 executados / 111 skips opt-in**, PASS.
- Auditoria: **28 casos**, 27 executados / um skip Windows neste host Linux,
  PASS. HTTP, filesystem e criptografia reais com contas sintéticas.
- Node: **20 grupos**, PASS. Compilação Python/JS, links relativos e diff check,
  PASS. Sem dependências ou migrações novas.
- Treze arquivos preservados byte a byte da base: Accounts, Export, Preview,
  HTML/CSS/JS; Assessment Report, Report Export e Executive Report; guia/helper
  de download v0.6.13 e verificadores ZIP stdlib v0.6.13/v0.6.15.
  Auth/API/Web recebem somente a integração opcional e o ajuste de query abaixo;
  conteúdos Web v0.6.17, contratos API/Auth v0.6.11 e política v1 permanecem.

## GitHub Actions da fonte

| Evento | Workflow | Run |
| --- | --- | --- |
| pull_request | Operator Web CI | [37183967730](https://github.com/brunosfs-droid/canca/actions/runs/37183967730) |
| pull_request | Operator Accounts CI | [37183967674](https://github.com/brunosfs-droid/canca/actions/runs/37183967674) |
| pull_request | PostgreSQL CI | [37183967666](https://github.com/brunosfs-droid/canca/actions/runs/37183967666) |
| pull_request | Python CI | [37183967670](https://github.com/brunosfs-droid/canca/actions/runs/37183967670) |
| pull_request | Optional Agent CI | [37183967665](https://github.com/brunosfs-droid/canca/actions/runs/37183967665) |
| push | Operator Web CI | [37183965241](https://github.com/brunosfs-droid/canca/actions/runs/37183965241) |
| push | Operator Accounts CI | [37183965234](https://github.com/brunosfs-droid/canca/actions/runs/37183965234) |
| push | Python CI | [37183965226](https://github.com/brunosfs-droid/canca/actions/runs/37183965226) |
| push | PostgreSQL CI | [37183965225](https://github.com/brunosfs-droid/canca/actions/runs/37183965225) |
| push | Optional Agent CI | [37183965230](https://github.com/brunosfs-droid/canca/actions/runs/37183965230) |

As etapas críticas incluem compilação/auditoria HTTP nativa e administração
offline nas quatro combinações; compilação e suíte Python; compilação,
transações e backup/restore nos dois PostgreSQL; Chromium; contratos,
interrupção/tamper e lifecycle/intervalo nativos do Agent. Etapas condicionais
da outra plataforma não contam como prova executada.

## Matriz de auditoria nativa

| Runner / Python | Casos | Executados | Skips previstos | Resultado |
| --- | --- | --- | --- | --- |
| ubuntu-latest / 3.10 | 28 | 27 | 1 Windows | PASS |
| ubuntu-latest / 3.12 | 28 | 27 | 1 Windows | PASS |
| windows-latest / 3.12 | 28 | 25 | 3 POSIX | PASS |
| windows-latest / 3.13 | 28 | 25 | 3 POSIX | PASS |

Os runs push também passaram nas quatro combinações. Symlinks nativos de
arquivo/diretório e UNC foram realmente exercitados em Windows. Os 24 casos
de contas offline v0.6.18 também passaram: 23 executados / um skip em Linux;
21 executados / três skips em Windows.

Os novos casos verificam:

- arquivo exclusivo/privado, esquema fixo, sequência e pareamento; criação
  inválida ou destino existente sem sobrescrita; aliases, hardlinks e FIFO;
- orçamento de 4096 bytes na fixture, reserva para fins e encerramento;
  oito requests admitidos, nona admissão negada e retomada após concluir;
- 32 requests concorrentes em oito threads, com 66 eventos ordenados;
  escritas curtas concluídas, escrita de zero bytes negada;
- append/truncamento, substituição por outro inode, hardlink e drift de
  privacidade; arquivos substitutos não recebem dados do descriptor anterior;
- falhas de fsync na abertura e no fim; prefixo preservado, sink invalidado e
  arquivo existente não reutilizado; interrupção abrupta em subprocesso;
- campos finais inválidos e rótulos de rotas não confiáveis sem eco de entrada;
- API/Web sem auditoria preservados; login, lista, relatório, preview, ambos
  os ZIPs, logout, grants próprios, origem negada, expiração e token forjado;
- usuário desconhecido/desabilitado, senha inválida e erros de backend sem
  copiar entrada, senha, token/hash, salt/hash ou erro bruto para JSONL;
- auditoria indisponível nega novo login/logout/leitura antes dos hooks/SQL;
  falha no fim pode seguir HTTP 200 e negar a admissão posterior;
- desconexão do cliente, inclusive a capturada no download Web, registrada
  como delivery_failed; falha do handler distinta de escrita concluída;
- CLI com destino existente retorna erro fixo/exit 2, sem eco do caminho.

O head inicial `04a557d3d41eb03f3990bffcb8f9e7f048139eb6` falhou em dois casos de
relatório sem query no Python 3.10. A falha permanece no histórico, sem declarar
essa fonte aprovada. A revisão qualificada normaliza somente a query exatamente
vazia para os defaults. Queries não vazias conservam parsing estrito, limite de
campos e rejeição de duplicatas. Campos desconhecidos, duplicados e separadores
inválidos continuam retornando 400 antes de SQL. Os dois casos antes falhos e
essas rejeições passaram nas quatro combinações do head corrigido.

## PostgreSQL, navegador e compatibilidade

- Python CI: **525 casos / 111 skips**, PASS; mesma contagem local. A mensagem
  backup_restore_failed do teste negativo de guardrail é esperada.
- PostgreSQL **16.15 / 17.11**: **188 casos por versão, sem skips**, PASS.
  O novo teste usa HTTP auditado e role SELECT-only reais: login, relatório,
  preview, dois downloads, grant negado antes de SQL e falha de auditoria
  antes de SQL/logout. DML negado; snapshots das **14 tabelas** e hashes de
  todos os arquivos do store permanecem iguais. O token anterior continua
  válido até o encerramento controlado; uma falha de auditoria não o revoga.
- Backup/restore lógico passou nas duas versões, com **14 tabelas / 20 arquivos**
  e replay. São ambientes descartáveis do CI.
- Chromium real a **1280 / 390 px**: autorização, seleção, resumo/hash, zero
  imports, 12 grupos em páginas 10+2, logout/reload e ambos os downloads, PASS.
  A fixture privada fechou o listener e verificou eventos pareados, IDs
  confiáveis, ausência de dados submetidos e listener_stopped. O log contém
  OPERATOR WEB AUDIT PASS; o arquivo JSONL temporário não foi publicado.
- Optional Agent: quatro combinações Linux/Windows e Python, PASS. Etapas
  systemd/SCM e intervalos/espera interrompida foram executadas nas respectivas
  plataformas; contratos, processo interrompido e adulteração offline preservados.

## Artefatos Web conferidos

Artifact **11295474942**, operator-web-synthetic-screens, do run PR Web
37183967730; fonte confirmada no head acima, não expirado no download,
**1132523 bytes**, SHA256 externo
`9656e4d4db73ec5710811bdd978d0490c3ec8cd550c65cd1e586cf61242260ab`.
Retenção de sete dias; fontes, runs e hashes permanecem registrados em Git.

Inventário de **14 membros fixos**, sem duplicatas, nomes estrangeiros ou
criptografia, conferido antes da leitura. Até 2 MiB por membro e 20 MiB no total;
nenhuma extração genérica. Todos os 14 payloads são byte a byte iguais à fixture
v0.6.18, incluindo os oito PNG. Os PNG do resumo mantêm 1280×3050 e 390×4627;
a inspeção visual da v0.6.17 corresponde aos mesmos bytes, sem nova inspeção
visual declarada neste registro. Nenhum JSONL de auditoria foi incluído.

| Payloads em 1280 / 390 px | SHA256 | Conferência |
| --- | --- | --- |
| preview JSON | `316b4b43ae7fc0cbfc5d291b6d8fd8ac2d9f988dee27dd68335a281eb5677535` | 3685 bytes, projeção da síntese completa PASS |
| report ZIP | `8b828ed3efb3b7714efe4ce96b8158ec753dfc400a4d71c9a848b7d391418bb9` | FILE PASS v0.6.13 |
| executive ZIP | `c39b02f37f3816a731179fea1b09a800a27ad649a4d97193bdc3944fcd795cf3` | EXECUTIVE FILE PASS v0.6.15 |

Os quatro ZIP passaram nos verificadores stdlib preservados: quatro membros
internos, quatro avaliações, dois findings históricos e dois grupos no executivo,
terminal vazia verificada. Os dois JSON concordam com a projeção por campos
explícitos da síntese completa. Evidência bruta/extraída, risco atual e referências
de ocorrências permanecem ausentes ou false conforme o contrato. Igualdade de
bytes comprova esta fixture/formato; hashes não comprovam autoria.

## Limites e validações adiadas

Nenhuma ação ou teste no LAB solicitado hoje. Nenhuma conta real, serviço,
configuração, banco, store ou alvo alterado. Gates operacionais e telas/downloads
posteriores continuam adiados; este CI não os declara aprovados. R1 e soaks
aceitos não precisam ser repetidos.

Default desativado. Cada execução auditada exige arquivo novo; não há append,
rotação, purge, retry, SIEM ou ativação/restart automático. Orçamento cheio nega
novos requests e conserva as reservas dos já admitidos. Falha de I/O/drift
invalida o sink: trabalho já admitido pode terminar, mas não há promessa de
gravar seus fins depois dessa falha. Restaurar o arquivo não libera o sink.

Falha no fim pode ocorrer depois de uma resposta ou revogação; não há rollback
do efeito já ocorrido. Linha completa observada após falha de fsync não comprova
persistência durável. Interrupção pode deixar início sem fim, linha parcial e
ausência de listener_stopped. Startup falho pode deixar arquivo privado novo;
o prefixo não é apagado nem completado artificialmente.

A cobertura é dos GET/POST/DELETE encaminhados após parsing HTTP e admissão
do worker/TLS. Falhas anteriores, saturação e métodos não encaminhados precisam
de logs de rede/OS/proxy próprios. Status preparado e escrita no socket não
comprovam recebimento ou salvamento pelo cliente. UTC depende do relógio do host.

Não é trilha imutável/assinada nem defesa contra administrador hostil. Checagens
detectam drift observado. Windows exige ACL restritiva na implantação futura;
CI nativo não qualifica ACLs, retenção, todos os filesystems ou restart operacional.
Identificadores autorizados ainda são metadados privados, não conteúdo publicável.

Collector portable permanece sem login Cancã; credenciais de alvo e mTLS de Node
seguem separados. AD/SSO, tenancy, RBAC ampliado e TLS/roles de produção continuam
decisões/gates próprios. Não há dependência de teste pelo mantenedor para integrar
este incremento.

[Contrato](../OPERATOR_SERVER_AUDIT_v0.6.19.md) ·
[ADR 0031](../ADR_0031_Operator_Server_Audit_v0.6.19.md) ·
[Compatibilidade anterior](OPERATOR_ACCOUNTS_CI_v0.6.18.md).
