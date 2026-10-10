# Cancã v0.6.93 — verificação pós-SIGKILL do grupo legado (R02)

## Problema e correção funcional

O adaptador de status legado usa grupos de processo POSIX. Enviar `SIGKILL` e aguardar apenas o **líder** pode ser insuficiente para provar que um descendente permaneceu incapaz de executar entre o fechamento do workspace A e a abertura do workspace B.

- Em **Linux**, após o SIGTERM, o prazo de graça, o SIGKILL e o `wait()` do líder, `_linux_running_group_member(pgid)` percorre `/proc/*/stat` e identifica processos que ainda pertencem ao grupo original.
- Processos `Z` (zombie) e `X` (dead) não executam e não bloqueiam; demais membros ativos exigem aguardo limitado a 0,75 s após o wait.
- Se não for possível inspecionar `/proc`, ou um membro persistir além do limite, a limpeza **falha fechada** com código sanitizado. A v0.6.92 garante que o coordenador entre em `recovery_required`, cancele outros jobs, limpe o cache e impeça a troca de workspace.
- Em outros sistemas POSIX e Windows, a lógica anterior permanece: esta qualificação de descendentes **não** garante encerramento em todas as plataformas.
- A verificação não cobre subprocessos que abandonam deliberadamente a sessão/grupo via `setsid`; esses cenários ainda exigem contenção adicional e homologação.

## Testes reprodutíveis

```bash
python -m unittest discover -s tests -p "test_workspace_legacy_jobs.py" -v
```

Os novos testes Linux/POSIX:
1. Simulam descendente persistente no grupo mesmo após o envio de SIGKILL e verificam o timeout limitado, erro sanitizado, cancelamento e quarentena, sem abrir B.
2. Executam um processo Python local sintético que ignora SIGTERM; confirmam escalonamento SIGKILL, encerramento efetivo, ausência de jobs remanescentes e abertura controlada do workspace B somente após quiescência.

Os testes existentes para cancelamento, processo filho/neto e perda de acesso continuam válidos. CI não executa autenticação ou varredura.

## Critérios e limitações de aceitação

Esta é uma melhoria de robustez do runtime, não uma declaração de conformidade operacional. E0 permanece `NOT RUN`, R02/T14 permanecem parciais, e testes de coletores reais/WinRM/SNMP, isolamento sob host comprometido, métricas de campo e recuperação cross-cluster T13/R20 dependem de laboratório autorizado. Em caso de quarentena, investigar e isolar os processos antes de reiniciar uma instância, nunca liberar automaticamente os jobs.
