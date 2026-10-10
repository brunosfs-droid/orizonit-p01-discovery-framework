# Cancã v0.6.90 — qualificação R02 multiprocesso com subprocessos reais e fixture sintética

## Objetivo e escopo

A v0.6.89 qualificou concorrência, `drain`, geração e latência do coordenador com operações em memória. Esta entrega exercita a **fronteira de processos** do adaptador de checkpoint legado (`P01_Workspace_Legacy_Jobs.checkpoint`) sob o coordenador, usando dois ou mais processos locais reais, mas **nenhum scanner de produção, credencial, banco, rede ou EVE-NG**.

Em Linux/POSIX, os processos criados executam um script Python sintético que apenas registra seu PID numa pasta temporária e aguarda. O adaptador permanece restrito ao comando de status read-only, usando `start_new_session` e encerramento do grupo de processos. O script sintético só é usado dentro deste harness, com `unittest.mock.patch` local.

## Execução offline

```bash
python docs/validation/ALPHA_R02_LEGACY_MULTIPROCESS_SMOKE_v0.6.90.py --cycles 2 --workers 2
python -m unittest discover -s tests -p "test_alpha_r02_legacy_multiprocess_smoke.py" -v
```

Requisitos: Linux/POSIX, Python padrão do ambiente e os módulos locais do repositório. O harness não é compatível com Windows e falha fechado em ambiente incompatível.

As entradas são limitadas a 1–8 ciclos e 2–4 processos concorrentes; valores booleanos e tamanhos fora dos limites são rejeitados. O tempo de espera de cada processo e do `close()` é delimitado.

## Critérios automatizados

1. Abrir o workspace A ou B e iniciar os processos de checkpoint sob o token de geração atual.
2. Aguardar a criação dos marcadores de PID e a admissão do número exato de jobs autorizados pelo coordenador.
3. Solicitar `close()`; cancelar todos os processos em andamento e assegurar que cada operação termine com `workspace_generation_stale`, sem entregar dados.
4. Verificar ausência de jobs/cache ativos, nenhuma thread remanescente, nenhum processo sintético em execução (zombies não executam) e rejeição do token da geração encerrada.
5. Alternar A/B entre os ciclos. Medir p50, p95 e máximo do tempo de fechamento em milissegundos, registrando número de operações canceladas.
6. Em falha, interromper os testes e tentar limpar somente os PIDs iniciados pela iteração ativa; não reutilizar um token antigo nem autorizar outra varredura.

A saída JSON contém `OFFLINE_MULTIPROCESS_QUALIFIED`, `scope: synthetic_local_status_processes`, `lab_executed: false`, `operational_go: false` e `threshold_qualification: not_established`. Uma falha emite `FAILED` e um código de erro genérico, sem caminhos ou nomes privados.

## Limites e pendências da Alpha

A qualificação comprova apenas o isolamento e o cancelamento nesta fixture local limitada. **Não comprova** que todos os collectors, adapters Windows, scanners SNMP ou operações AUTH/FULL/POST reais são canceláveis, nem determina SLA/limites de p95, RPO/RTO ou comportamento sob múltiplos servidores. A execução E0 no EVE-NG e a matriz R01–R06 permanecem abertas; T14 e R02 exigem carga real e evidências assinadas.

O CI deve passar pelos oito workflows obrigatórios antes de integração. A execução do teste no Python CI não promove automaticamente nenhum gate E0 de `NOT RUN` para `PASS`.
