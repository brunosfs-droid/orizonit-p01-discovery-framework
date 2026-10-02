# Cancã v0.5f.3 — Agendamento explícito e revisão após interrupção

Data: 01/10/2026 (-03). Status: **CANDIDATE — LAB R1 pendente**.
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

Próximo gate: [R1 Windows + Rocky](LAB_SCHEDULER_v0.5f.3_R1.md), duas tentativas com
60s reais, mudança de policy entre elas, fim de orçamento ocioso, kill durante espera
de uma segunda sessão, terceiro start exige revisão com zero invocações canônicas.
A fixture retém provas/journals/sidecars, e o helper remove somente seu serviço.

Limites: R1 curto, sem prova multi-day; grants live sempre negados; principal do serviço
não qualificado para AUTH/FULL/upload; retenção automática adiada. Recovery exige
revisão/reconciliação manual e preservação das evidências. Nenhum aceite v0.5f.3 é
inferido dos LABs anteriores. [Contrato operacional](../agent/SCHEDULER.md).
