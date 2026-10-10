# Cancã v0.6.92 — quarentena fail-closed após falha de limpeza de subprocesso (R02)

## Falha corrigida

O adaptador de status legado executa um subprocesso local read-only sob o coordenador de workspace. Antes desta mudança, a rotina `_stop(child)` podia falhar ao finalizar o grupo de processos; apesar disso, o contexto de execução encerrava o job, possibilitando a transição para outro workspace enquanto um filho da geração anterior possivelmente permanecia ativo.

Um erro genérico no adaptador não é suficiente para preservar o isolamento entre A/B. O coordenador deve entrar em quarentena quando **não há garantia de encerramento** de subprocesso associado a uma geração.

## Mudança funcional

- `Coordinator.fail_closed()` é uma operação **interna e confiável** que, sob o lock de condição do coordenador, transita para `recovery_required`, aciona cancelamento das operações emprestadas, elimina cache e notifica os jobs. Chamadas repetidas são idempotentes; a instância comprometida não se reabre.
- `P01_Workspace_Legacy_Jobs.checkpoint()` captura qualquer exceção comum durante `_stop(child)`, aciona `operation.coordinator.fail_closed()` **antes** de liberar o job e retorna um erro sanitizado `workspace_legacy_job_failed`. Detalhes de erro e caminhos internos não são expostos.
- O novo comportamento protege a transição de workspace mesmo quando a operação anterior já havia terminado seu comando principal, ou quando a permissão foi revogada antes da tentativa de limpeza.
- Recuperação: não forçar a reabertura da instância em `recovery_required`. O operador deve isolar processos sobreviventes, inspecionar causas da limpeza incompleta e recriar a sessão/coordenador em contexto operacional controlado, com geração e autorização novas. Não há recuperação automática nem execução de scanners nesta entrega.

## Testes

Os testes já existentes foram expandidos:
- `tests/test_workspace_legacy_jobs.py`: injeta falha na limpeza do subprocesso depois de retorno bem-sucedido do comando e após revogação de leitura; exige quarentena, cancelamento de outros jobs, erro redigido, ausência de reabertura de B e estado consistente.
- `tests/test_workspace_coordinator.py`: valida `fail_closed()` idempotente, cancelamento de jobs emprestados, limpeza do cache e proibição de tokens/abertura após a falha.

Os testes são automáticos no Python CI e no Workspace Foundation CI. A falha de limpeza é injetada sinteticamente; o código não mata processos arbitrários nem simula homologação real.

## Critérios de fechamento

Esta entrega reduz uma lacuna de R02, mas **não encerra R02/T14 nem E0**. Ainda faltam falhas reais de SIGTERM/SIGKILL em múltiplos hosts, processos que deliberadamente escapem dos grupos de processo, Windows, AUTH/FULL/POST, coleta autorizada no EVE-NG, benchmarks representativos e evidências do mantenedor. A matriz de aceitação permanece parcial; os dez gates E0 continuam `NOT RUN`.

Uma aprovação dos workflows não equivale à aprovação operacional da Alpha.
