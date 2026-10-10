# Cancã v0.6.89 — ensaio offline R02: drain, cancelamento e alternância A/B

## Objetivo
R02/T03/T14 ainda exige evidência de cancelamento, ausência de mistura entre workspaces e comportamento sob carga. Esta entrega acrescenta um **ensaio sintético, reproduzível e limitado** que exercita a classe real `Coordinator` com lease **somente em memória**. Não executa scanners, WinRM, SSH, SNMP, PostgreSQL, nem acessa o EVE-NG.

## Procedimento
```bash
python docs/validation/ALPHA_R02_COORDINATOR_LOAD_SMOKE_v0.6.89.py --cycles 5 --workers 4
python -m unittest discover -s tests -p 'test_alpha_r02_coordinator_load_smoke.py' -v
```

- Entrada limitada a **1–50 ciclos** e **1–16 jobs concorrentes**; entradas booleanas e limites incorretos são rejeitados.
- Cada ciclo alterna os workspaces A e B, abre uma geração, empresta jobs autorizados no contexto atual, sincroniza o início, solicita `close()` com timeout limitado e exige cancelamento de **todos** os jobs.
- Cada job deve observar `workspace_generation_stale` após cancelamento. Um token de geração anterior deve ser rejeitado até quando o ator simulado tem autorização de leitura em ambos os workspaces.
- Depois do drain, não pode haver jobs ou cache remanescentes. As threads do teste são encerradas antes da troca seguinte.
- Resultados incluem cancelamentos cercados, tokens obsoletos negados, **p50/p95/max do tempo de close** e **pico de alocações Python via tracemalloc**. Valores servem para análise de tendência; não existe limiar ou SLA afirmado nesta etapa.
- Testes unitários verificam alternância, contagens, quantis, limites e saída sanitizada. O Python CI executa automaticamente a suíte ao descobrir arquivos `test_*.py`.

## Critérios, limites e próxima homologação
O status `OFFLINE_QUALIFIED` significa exclusivamente que as invariantes sintéticas passaram. Os resultados contêm invariavelmente `operational_go: false`, `lab_executed: false`, `scope: in_memory_coordinator_only` e `threshold_qualification: not_established`.

**Não fecha R02 nem T14.** Ainda é necessário medir múltiplas sessões/processos e I/O real dos adapters/collectors legados em laboratório autorizado, observar cancelamento de AUTH/FULL/POST, estabelecer baselines de p50/p95/RAM em hardware representativo e coletar evidências E0. A matriz R01–R06 permanece parcial; EVE-NG E0 continua dez vezes NOT RUN. Cross-cluster T13/R20 também permanece aberto.

Este incremento evita quaisquer tarefas destrutivas, exposição de credenciais ou alteração no schema de banco.
