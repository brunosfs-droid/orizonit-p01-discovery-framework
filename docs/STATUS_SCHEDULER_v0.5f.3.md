# Cancã v0.5f.3 — Agendamento explícito e revisão após interrupção

Data do candidato: 01/10/2026 (-03). Aceite: 02/10/2026 (-03).
Status: **LAB VALIDATED — R1 curto e soak estendido offline de 10 ticks**.
Refs #83; [ADR 0010](ADR_0010_Scheduler_v0.5f.3.md).

Hosts Windows/Linux e scheduler: v0.5f.3. Wrapper/policy/journal canônico permanecem
v0.5f.0/schema v0.5f; runtime v0.5e.6/schema v0.5e. O aceite anterior dos hosts
manuais v0.5f.1/v0.5f.2 permanece histórico e não qualifica o agendamento novo.

Implementado: opt-in desativado por padrão, instalação com grants negados e scheduler
desativado, orçamento de 1..10000 tentativas, intervalo validado de 60..86400 segundos,
delay após conclusão, releitura de policy/config por ciclo e lock compartilhado.
Sem catch-up, overlap, retry, timer/autostart ou recovery automático do SO.

Journal de sessão separado em logs/scheduler com JSON/SHA256, identidade e digest da
config; running ou halted bloqueiam o próximo start, inclusive se o operador desativar
o scheduler e escolher modo manual. Falha/review interrompe; fim de orçamento deixa
o host ocioso. Stop acorda a espera e aguarda a operação em andamento. Não cancela
AUTH/FULL/POST. Sem transporte/credenciais persistidos; upload continua invocation-only.

Regressão local: 204 testes PASS, incluindo 17 contratos novos; 200 ticks negados usam
relógio acelerado somente no teste. CI inclui SCM real (Windows Python 3.12/3.13),
systemd real (Ubuntu Python 3.10/3.12), smoke manual e novo helper scheduled_agent_soak.
Consultar o PR de integração para resultados nativos do commit; não confundir testes
unitários acelerados com duração real nem CI com aceite P01LAB.

[R1 Windows + Rocky](LAB_SCHEDULER_v0.5f.3_R1.md) aprovado: PASS/exit 0 em
P01-MGMT01 (Python 3.13.15/pywin32 312) e P01-LNX-RKY01 (Rocky 10.2/Python
3.12.13/systemd 257). Dois ticks a 60s reais, ciclos de 60,525s e 60,174s,
policy reread, state intacto, fim do orçamento ocioso, interrupção de uma segunda
sessão e terceiro start bloqueado com zero invocações. Três journals e três sessões
por host, auditorias PASS, fixtures retidas e serviços removidos. Journalctl e
query independente no Rocky corroboram os resultados. [Aceite e limites](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md).
Bytes dos proof/journals não foram anexados; validade é a auditoria reportada pelo
helper. HEAD do operador não foi capturado. CI da implementação: PR #93, Python e
quatro jobs nativos PASS.

[Soak estendido](validation/SCHEDULER_P01LAB_EXTENDED_v0.5f.3.md) aprovado em
02/10/2026: PASS/exit 0 nos dois hosts, 10 ticks a 60s, ciclos de 540,911s Windows
e 540,310s Rocky, 11 journals/3 sessões por host e auditorias PASS. Mesmos gates de
policy/state/orçamento, interrupção preservada e restart em revisão sem replay.
HEAD Windows capturado: 84a791e596311a123ba179325f2af8234d2c31a1; HEAD Rocky não
mostrado separadamente. Aceite baseado nas duas capturas desta nova rodada;
proof/journals brutos não foram anexados. Fixtures novas retidas e serviços removidos.

Limites: soak offline limitado de cerca de 9 minutos, sem prova multi-day; grants live sempre negados; principal do serviço
não qualificado para AUTH/FULL/upload; retenção automática adiada. Recovery exige
revisão/reconciliação manual e preservação das evidências. R1 curto e rodada estendida
mantêm registros separados, sem extrapolar seus escopos. [Contrato operacional](../agent/SCHEDULER.md).
