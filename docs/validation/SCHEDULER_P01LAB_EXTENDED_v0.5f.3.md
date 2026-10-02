# P01LAB — Aceite do soak estendido offline v0.5f.3

Data: 02/10/2026 (-03). Evidência: duas capturas fornecidas por Bruno Feitoza.
**LAB VALIDATED no escopo de 10 ticks com intervalo real de 60s**, em Windows e
Rocky. Complementa o [R1 curto](SCHEDULER_P01LAB_R1_v0.5f.3.md).

| Campo observado | P01-MGMT01 | P01-LNX-RKY01 |
| --- | --- | --- |
| Ambiente | Windows, Python 3.13.15, pywin32 312 | Rocky, Python 3.12.13 |
| Versões serviço/scheduler | 0.5f.3 / 0.5f.3 | 0.5f.3 / 0.5f.3 |
| Resultado / exit | SCHEDULED AGENT SOAK PASS / 0 | SCHEDULED AGENT SOAK PASS / 0 |
| Starts / scheduled ticks | 3 / 10 | 3 / 10 |
| Intervalo real | 60s | 60s |
| Primeiro ciclo limitado | 540,911s | 540,310s |
| Journals / sessões auditadas | 11 / 3 | 11 / 3 |
| Auditorias de journal/scheduler | PASS / PASS | PASS / PASS |
| SHA256 e campos de contrato | válidos, segundo o helper | válidos, segundo o helper |
| Restart em revisão | 0 invocações | 0 invocações |

Nos dois hosts: policy reread, grants negados, state de origem intacto, host ocioso
após orçamento, recovery automático desabilitado, intenção da espera interrompida
preservada, lock readquirido, sessões unfinished/review_required e serviço removido.
As fixtures foram retidas; o terceiro start bloqueado é o comportamento esperado.

Fixture Windows: `C:\Canca\scheduled-lab\P01-SCHEDULED-R1-4ccc9c400f74`.
Fixture Rocky: `/var/lib/canca/scheduled-lab/P01-SCHEDULED-R1-2d1f559741a6`.
Checkout Windows: HEAD `84a791e596311a123ba179325f2af8234d2c31a1` capturado.
No Rocky foi exibido o pacote `/root/p01/canca-agent-v0.5f.3`, versão do Python e
resultado completo. HEAD/hash do pacote Rocky não foi mostrado separadamente.

## Alcance do aceite

As capturas mostram duas execuções offline de cerca de 9 minutos por primeiro
ciclo, com auditorias reportadas pelo helper. Não foram fornecidos bytes brutos
de proof/journals desta rodada nem consulta/journalctl independente novo. O aceite
se limita ao resultado visível; não afirma verificação externa dos arquivos retidos.

Não qualifica soak multi-day, grants live, principal de serviço para AUTH/FULL/POST,
cancelamento de operação em andamento ou reconciliação de transporte. Não é preciso
repetir este teste agora, reinstalar serviços removidos pelo helper ou eliminar
intenções interrompidas. Evidências e fixtures devem permanecer preservadas.

Capturas originais: `image(20261002-124406).png` e
`image(20261002-125258).png`. O pacote formal de evidências desta rodada mantém os
bytes originais e um inventário SHA256; não altera o pacote histórico do R1 curto.
