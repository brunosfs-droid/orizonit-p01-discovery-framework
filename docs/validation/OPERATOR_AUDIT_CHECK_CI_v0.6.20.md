# Revisão offline de auditoria v0.6.20 — registro de qualificação

Data: 04/10/2026 (-03). Status: CANDIDATE operacional; código qualificado no CI.

Fonte executável: `43b7a510e92f3d01b993a1847cd1695879ef85bf`.
Tree completo: `7cb960266b91899fc3414cf67e5230f5f7e9564e`.
Base v0.6.19: `000c1a72179ffdc35b22869e7fa8d0907c545f58`.
Dez runs / **24 jobs PASS** nesse head, com **120 etapas críticas** conferidas
como efetivamente executadas e timestamps preenchidos. Tree remoto e local
completos iguais, incluindo binários/branding. O commit final deste registro e
de próximos passos muda somente dois documentos, sem alteração de código.
[PR #120](https://github.com/brunosfs-droid/canca/pull/120).

## Verificação local e preservação

- Python: **555 casos, 443 executados / 112 skips opt-in**, PASS.
- Revisão offline: **30 casos, 29 executados / um skip Windows**, PASS neste
  host Linux; incluídos na suíte completa. Node: **20 grupos PASS**.
- Compilação, diff check e links relativos dos documentos modificados, PASS.
- Dezessete fontes preservadas byte a byte da base: Auth/API/Web/Audit,
  Accounts/Export/Preview, HTML/CSS/JS; Assessment Report/Report Export/Executive
  Report; guia/helper v0.6.13 e verificadores ZIP stdlib v0.6.13/v0.6.15.
  Nenhum endpoint, formato de log/relatório, driver ou migração novo.

## GitHub Actions da fonte

| Evento | Workflow | Run |
| --- | --- | --- |
| pull_request | Operator Accounts CI | [37195906860](https://github.com/brunosfs-droid/canca/actions/runs/37195906860) |
| pull_request | PostgreSQL CI | [37195906858](https://github.com/brunosfs-droid/canca/actions/runs/37195906858) |
| pull_request | Operator Web CI | [37195906851](https://github.com/brunosfs-droid/canca/actions/runs/37195906851) |
| pull_request | Python CI | [37195906874](https://github.com/brunosfs-droid/canca/actions/runs/37195906874) |
| pull_request | Optional Agent CI | [37195906853](https://github.com/brunosfs-droid/canca/actions/runs/37195906853) |
| push | Operator Accounts CI | [37195903710](https://github.com/brunosfs-droid/canca/actions/runs/37195903710) |
| push | PostgreSQL CI | [37195903721](https://github.com/brunosfs-droid/canca/actions/runs/37195903721) |
| push | Operator Web CI | [37195903616](https://github.com/brunosfs-droid/canca/actions/runs/37195903616) |
| push | Python CI | [37195903648](https://github.com/brunosfs-droid/canca/actions/runs/37195903648) |
| push | Optional Agent CI | [37195903722](https://github.com/brunosfs-droid/canca/actions/runs/37195903722) |

Etapas críticas: compilações e testes de contas/auditoria/revisão nas quatro
combinações; compilações e suíte Python; compilações/transações/backup-restore
nos dois PostgreSQL; Chromium; contratos/interrupção/tamper e lifecycle/intervalo
nativos do Agent. Etapas condicionais da outra plataforma não contam como prova.

## Matriz nativa de revisão

| Runner / Python | Casos | Executados | Skips previstos | Resultado |
| --- | --- | --- | --- | --- |
| ubuntu-latest / 3.10 | 30 | 29 | 1 Windows | PASS |
| ubuntu-latest / 3.12 | 30 | 29 | 1 Windows | PASS |
| windows-latest / 3.12 | 30 | 27 | 3 POSIX | PASS |
| windows-latest / 3.13 | 30 | 27 | 3 POSIX | PASS |

Push e PR passaram nas quatro combinações. Symlinks nativos e UNC foram realmente
exercitados em Windows. Os 24 casos de contas e os 28 do produtor de auditoria
também passaram, conservando seus skips nativos previstos.

Os novos casos cobrem schema independente e chaves repetidas; tipos/UTC/limites;
sequência/listener/pairs e IDs repetidos; oito requests abertos e nona admissão
incompatível; classes HTTP/outcomes; relógio regressivo; encerramento/abertura/
última linha não interpretada; linha completa inválida não ocultada como prefixo;
redação de saída; hash esperado; arquivo privado/regular/limites/aliases/hardlinks;
append, substituição e drift de privacidade durante leitura; produtor real cheio;
fsync final falho; subprocesso com os._exit; login/logout/grant negado via HTTP;
CLI com exits 0/3/2 e argumentos inválidos sem eco de entrada.

### Correção medida no Windows

O head inicial `3d9629976697d8a140d998ff82a69162c5024631` falhou em cinco casos
de revisão por runner Windows, nas duas versões de Python. A fonte não foi
declarada qualificada; os runs Accounts 37195561989/37195590172 permanecem
históricos com falha. A primeira implementação comparava os stamps completos
de caminho e descritor como se seus timestamps tivessem a mesma semântica.

A revisão compara o stamp FD antes/depois via fstat e o stamp do caminho
antes/depois via lstat, mantendo binding de identidade/modo/proprietário/links/
tamanho entre APIs. Não exige igualdade cruzada de ctime. A diferença de ctime
entre APIs Windows também é documentada no
[CPython #157671](https://github.com/python/cpython/issues/157671).
Dois casos de regressão confirmam aceitação de ctime estável diferente entre
APIs e rejeição de mudança observada no FD, mesmo com bytes/caminho iguais.
Os cinco casos antes falhos e as rejeições de drift passaram nos runners nativos.

## PostgreSQL, Chromium e Agent

- Python CI: **555 casos / 112 skips**, PASS, mesma contagem local. A mensagem
  backup_restore_failed do teste negativo de guardrail é esperada.
- PostgreSQL **16.15 / 17.11**: **188 casos por versão, sem skips**, PASS.
  O teste auditado SELECT-only agora revisa seu prefixo após fsync falho:
  open_prefix, um request sem fim, nenhum listener_stopped. Os fins observados
  concordam com a checagem independente. Saída sem assessment/operador/senha/
  token; **14 tabelas e hashes do store invariantes**, DML e SQL não autorizado
  negados. Não há novo acesso ao banco pela ferramenta de revisão.
- Backup/restore lógico nas duas versões: **14 tabelas / 20 arquivos e replay**,
  PASS, em ambiente descartável do CI.
- Chromium **1280 / 390 px**, PASS: seleção/grants, resumo/hash/paginação,
  zero imports, logout/reload e ambos os downloads. Após fechar os workers,
  inspect_log confirmou closed/zero pendentes/contagens iguais à checagem
  independente e agregados sem IDs privados. A fixture encerrou com exit 0;
  o harness registrou OPERATOR WEB AUDIT PASS. JSONL temporário não publicado.
- Agent: contratos/interrupção/tamper, lifecycle systemd/SCM e intervalos reais/
  espera interrompida passaram nas plataformas correspondentes.

## Artefatos Web

Artifact **11301246387**, operator-web-synthetic-screens, run PR Web 37195906851;
head confirmado na fonte acima, não expirado no download. **1132513 bytes**,
SHA256 externo `f547ff5074021f2ad26c26e0e8631096c981ccb91b9537013fa90dcb1701e76b`.
Retenção de sete dias; inventário/fontes/runs/hashes registrados em Git.

Inventário de **14 membros fixos**, sem duplicatas/nomes extras/criptografia,
conferido antes da leitura: até 2 MiB por membro / 20 MiB no total, sem extração
genérica. **13 dos 14 payloads idênticos à v0.6.19**. Os quatro ZIP e dois JSON
mantêm bytes/hashes; os ZIP passaram nos verificadores canônicos preservados.

| Payloads 1280 / 390 px | SHA256 | Conferência |
| --- | --- | --- |
| preview JSON | `316b4b43ae7fc0cbfc5d291b6d8fd8ac2d9f988dee27dd68335a281eb5677535` | 3685 bytes; acordo canônico preservado pela igualdade de bytes |
| report ZIP | `8b828ed3efb3b7714efe4ce96b8158ec753dfc400a4d71c9a848b7d391418bb9` | FILE PASS v0.6.13 |
| executive ZIP | `c39b02f37f3816a731179fea1b09a800a27ad649a4d97193bdc3944fcd795cf3` | EXECUTIVE FILE PASS v0.6.15 |

Quatro avaliações, dois findings históricos, dois grupos executivos e página
terminal vazia verificados. Formatos/semântica de evidência e risco preservados.

Sete PNG idênticos. assessments-1280.png mudou para 63700 bytes, SHA256
`9cc744f39665534deab0eb762e7b892f6378344e0ef95200f334d9ea288266a0`.
Comparação de pixels limita a diferença ao retângulo (84,321)–(1196,402), no
bloco Operador/Sair. As duas imagens foram inspecionadas: mesmos conteúdos e
dimensões 1280×900; nenhuma mudança de fonte HTML/CSS/JS. Não se declara igualdade
de bytes dessa imagem nem causa específica para a diferença. Os PNG do resumo
mantêm 1280×3050 e 390×4627 e os mesmos bytes já inspecionados na v0.6.17.
Nenhum JSONL de auditoria ou relatório agregado privado integra o artifact.

## Limites e validações adiadas

Nenhum teste/ação de LAB solicitado. Nenhuma conta real, serviço, configuração,
banco, store ou alvo alterado. Gates operacionais/manuais permanecem adiados;
R1 e soaks aceitos não precisam ser repetidos. Windows ACLs e todos os filesystems
não são qualificados por esta matriz nativa.

Revisão estrutural não atesta autoria, autorização real dos IDs, integridade
contra administrador hostil, fsync durável ou recebimento/salvamento do cliente.
Prefixo pode estar ativo ou interrompido; linha sem newline não é interpretada
e seu hash inclui a cauda. Bytes completos após fsync falho podem ser legíveis
sem prova de persistência. Nenhum resultado é fabricado ou registro reparado.

Snapshot vale somente para os bytes estáveis observados; não congela o arquivo,
segue alterações futuras ou substitui logs de rede/OS/proxy. Arquivos vazios ou
sem início completo não são prefixos verificáveis. Não há SIEM/rotação/retenção,
endpoint, escrita SQL ou ativação/restart automático. Collector portable segue
sem login Cancã; credenciais de alvos e mTLS de Node permanecem separados.

[Contrato](../OPERATOR_AUDIT_CHECK_v0.6.20.md) ·
[ADR 0032](../ADR_0032_Offline_Operator_Audit_Check_v0.6.20.md) ·
[Produtor qualificado](OPERATOR_SERVER_AUDIT_CI_v0.6.19.md).
