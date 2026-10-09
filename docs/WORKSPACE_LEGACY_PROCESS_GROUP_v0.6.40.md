# Cancã v0.6.40 — cancelamento de grupo de processos legados (R02/T03)

Status: **candidate**, sujeito aos workflows do último SHA e revisão. Continuação
da v0.6.39 já integrada à main via PR #150. Não habilita scanners, AUTH, FULL,
export, upload nem executor arbitrário; mantém somente o comando privado
`P01_Discovery_Node.py status --json`, sem publicação de stdout/stderr.

## Risco reduzido

A implementação anterior terminava o PID principal e liberava o job do
coordenador, mas um subprocesso criado pelo processo principal podia continuar
em segundo plano com uma credencial/contexto operacional antigo. Em POSIX a
execução já ocorria em uma sessão nova (`start_new_session=True`). Agora o
descarte sinaliza todo o grupo de processos (`SIGTERM` e, após janela limitada
de 350 ms, `SIGKILL`) **mesmo que o processo principal já tenha terminado**,
esperando pelo líder antes de liberar o job registrado. Timeout, fechamento
concorrente e saída normal usam o mesmo cleanup.

## Evidências/critério de aceite

- Regressão original: permissões, raízes, troca de workspace, revoke, timeout,
  saída não zero redigida, `status` somente, nenhum subprocesso após recusa.
- Três testes Linux adicionais com processos-filhos reais de fixture, sem rede:
  descendente órfão após exit0, timeout de pai com descendente e close concorrente.
- Nenhum job registrado pode sobreviver à devolução do `close` em cenários
  testados; token antigo deve continuar inválido.
- `Python CI`, `Workspace Foundation CI` em PostgreSQL 16/17 e demais
  workflows do último SHA devem passar. **LAB EVE-NG não homologado.**

## Limitações explícitas

- POSIX: cobre descendentes que continuam no grupo original. Processos capazes
  de abrir nova sessão (`setsid`), mudar grupos, iniciar daemons remotos,
  ou manter trabalho fora da árvore de execução **não** são contidos.
- Windows: a implementação ainda encerra apenas o processo principal; o
  encerramento completo da árvore requer Windows Job Objects e teste operacional.
- O subprocesso autorizado é apenas a leitura `status`; sucesso não indica
  integridade efetiva da coleta. A aplicação não publica processos `run`.
- Não confundir CI Linux com homologação de cancelamento de scanners ativos,
  transações SQL, rede, sessões SSH/WinRM ou tratamento de credenciais.

R02 segue **PARCIAL**, com implementação futura de adapters AUTH/FULL sob
contrato explícito de interrupção, nonce de job, idempotência e sandbox
operacional. R04/R05 (observações e import seletivo) e R06/E0 ficam abertas.
