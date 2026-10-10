# Cancã v0.6.91 — R02: revogação e perda de lease com processos locais reais

## Objetivo

A v0.6.90 verificou que processos de checkpoint são cancelados pelo fechamento do workspace. Esta entrega cobre **duas falhas assíncronas independentes do fechamento**:

1. Revogação da permissão de leitura **depois** que dois processos já iniciaram a execução;
2. Perda do lease do coordenador **durante** a execução de dois processos.

O teste `tests/test_alpha_r02_live_revoke.py` usa o adaptador real `P01_Workspace_Legacy_Jobs.checkpoint` e a implementação real do coordenador, com lease/ACL em memória e script Python local artificial. O teste não usa PostgreSQL, EVE-NG, conexões de rede, credenciais, SSH, WinRM, SNMP, AUTH/FULL ou coleta real.

## Execução reproduzível

```bash
python -m unittest discover -s tests -p "test_alpha_r02_live_revoke.py" -v
```

O teste é restrito a Linux/POSIX porque depende da terminação controlada de grupos de processos. O Python CI o descobre pela suíte padrão `test_*.py`.

## Invariantes verificadas

- O evento de falha só é injetado após confirmar **dois subprocessos em execução** e dois jobs admitidos.
- **Revogação:** cada worker deve terminar com `workspace_access_denied`, sem entregar resultados, sem jobs/cache remanescentes e com os subprocessos terminados; após fechar A e abrir B, o token antigo de A deve falhar com `workspace_generation_stale`.
- **Perda de lease:** cada worker deve falhar com `workspace_lease_lost`; estado `recovery_required`, nenhum resultado ou subprocesso ativo e nenhuma reabertura de B aceita pela instância comprometida.
- Erros de executor, processos sobreviventes ou entregas tardias reprovam a suíte.
- Os recursos sintéticos são limpos no fim da execução. Nenhum comando externo é selecionável pela API do produto.

## Limites

A qualificação avalia ACL simulada e lease simulado com **subprocessos Python reais** no Linux. Não cobre revogação e regrant atômicos no mesmo intervalo, credenciais e coletores reais, coordenação PostgreSQL multi-host, plataformas Windows, SLA/RTO ou recuperação entre clusters. O aceite E0 continua dez vezes `NOT RUN`; **R02/T14 e R06 permanecem parciais**, e a Alpha não está homologada.

Não interpretar green CI como execução em EVE-NG. Os resultados não emitem aprovação operacional.
