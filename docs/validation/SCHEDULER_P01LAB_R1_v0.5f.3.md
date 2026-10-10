# Cancã — Aceite do agendador v0.5f.3 / P01LAB R1

Data: 02/10/2026 (-03). Status: **LAB VALIDATED para o R1 offline de ciclos limitados e revisão após interrupção**.
Refs Issue #83; [ADR 0010](../ADR_0010_Scheduler_v0.5f.3.md).
Implementação: [PR #93](https://github.com/brunosfs-droid/canca/pull/93),
main de referência ac9c5ce7f927ff274b6a0292a8b8242957097cf5; candidato CI 2cb49fd8440ea3b53b34c45c266c02360874a31b.
O hash HEAD do checkout do operador não aparece nestas oito capturas. A correlação
é pelo helper versionado, versões 0.5f.3 reportadas, atualização visível de arquivos
no Windows e git archive/SCP/extract para o Rocky, sem inventário de deployment fornecido.

## Resultados observados

Oito capturas originais foram examinadas; mostram uma execução em cada host.
Visões repetidas da mesma fixture não são contadas como rodadas adicionais.

| Campo | Windows P01-MGMT01 | Rocky P01-LNX-RKY01 |
|---|---|---|
| Resultado | SCHEDULED AGENT SOAK PASS | SCHEDULED AGENT SOAK PASS |
| Exit LAB | 0 | 0 |
| service_version / scheduler_version | 0.5f.3 / 0.5f.3 | 0.5f.3 / 0.5f.3 |
| Python | 3.13.15; venv do checkout | 3.12.13; /usr/bin/python3 |
| Host do serviço | SCM; pywin32 312 | Rocky 10.2 Red Quartz; systemd 257; PID 1 systemd |
| Starts / ticks do primeiro ciclo | 3 / 2 | 3 / 2 |
| Intervalo real configurado | 60 s | 60 s |
| Duração do ciclo medida pelo helper | 60,525 s | 60,174 s |
| policy_reread / all_grants_denied | true / true | true / true |
| source_state_unchanged / budget_idles_host | true / true | true / true |
| automatic_recovery_enabled | false | false |
| interrupted_wait_intent_preserved | true | true |
| restart_review_invocations | 0 | 0 |
| lock_reacquired / service_removed | true / true | true / true |
| journal_audit | JOURNAL AUDIT PASS; 3 journals | JOURNAL AUDIT PASS; 3 journals |
| scheduler_audit | SCHEDULER AUDIT PASS; 3 sessões | SCHEDULER AUDIT PASS; 3 sessões |
| sha256_valid / contract_fields_valid, ambas auditorias | true / true | true / true |
| unfinished_session / review_required | true / true | true / true |
| evidence_retained | true | true |

Fixtures retidas pelo helper:

- Windows: `C:\Canca\scheduled-lab\P01-SCHEDULED-R1-74eab0f492e9`.
- Rocky: `/var/lib/canca/scheduled-lab/P01-SCHEDULED-R1-69e3e937d4c7`.

O comando Windows usa tests/scheduled_agent_soak.py com --lab-root C:\Canca\scheduled-lab
 e --node-id P01-MGMT01. O archive exporta HEAD agent/runtime/tests/docs e SCP
termina em 100% para 192.168.100.50. No Rocky, a extração ocorre em
/root/p01/canca-agent-v0.5f.3; o comando usa --lab-root /var/lib/canca/scheduled-lab
 e --node-id P01-LNX-RKY01. A checagem Python 3.10+ passa. SELinux Enforcing é
mostrado no preflight; isso não qualifica todas as políticas/labels possíveis.
O Windows Server 2022 é a identidade do host já registrada no LAB anterior;
a versão do sistema Windows não foi novamente exibida nesta rodada.

## Interrupção e inspeção independente no Rocky

O journalctl distingue registros históricos v0.5f.2 dos novos v0.5f.3:

- 00:19:06: PID 3929 inicia o worker v0.5f.3; às 00:20:06 registra completed,
  reason=max_invocations, invocations=2. Stop normal às 00:20:08.
- 00:20:08: PID 3949 inicia a segunda sessão e termina com status=9/KILL,
  a interrupção intencional durante a espera do helper.
- 00:20:10: PID 3969 inicia o terceiro start, registra halted/review_required
  com invocations=0 e para normalmente.

O SIGKILL e a sessão inacabada são parte do ensaio, não uma falha do resultado PASS.
unfinished_session=true e review_required=true são esperados: o intent running da
segunda sessão foi preservado, e o terceiro start ficou bloqueado. Não apagar
esse intent para liberar replay. A ausência de recovery foi verificada na janela
observada pelo helper; não se extrapola para estabilidade de longa duração.

A captura final consulta a config da fixture correta e retorna installed=false,
state=not_installed, main_pid=0. É o resultado esperado após service_removed=true.
Não há limpeza adicional ou motivo para reinstalar o serviço. O journal histórico
e a fixture permanecem. No Windows, remoção/preservação são reportadas pelo helper;
esta rodada não forneceu uma inspeção separada do SCM/Event Log.

## Evidências e limites do aceite

| Captura | Evidência visível |
|---|---|
| image(20261002-031351).png | Windows Python/pywin32, comando, PASS e resumo completo com fixture |
| image(20261002-031441).png | Exit LAB Windows 0 |
| image(20261002-031606).png | Mesma fixture Windows, exit 0, git archive e SCP concluído |
| image(20261002-031814).png | Rocky OS/Python/systemd/PID 1/SELinux e guard de versão |
| image(20261002-032022).png | Extração v0.5f.3, comando Rocky e PASS |
| image(20261002-032055).png | Mesmo PASS/fixture Rocky e Exit LAB Rocky 0 |
| image(20261002-032122).png | Journal independente: orçamento, kill, revisão sem invocação, stops |
| image(20261002-032315).png | Fixture correta, query do serviço removido e PID 0 |

Os originais e SHA256 por imagem são preservados no pacote de evidências R1.
As auditorias de JSON/SHA256/campos/identidade são os resultados do helper nativo
mostrados nas capturas. Bytes dos proof/journals/sidecars retidos nos hosts não foram
anexados; não houve segunda verificação independente desses bytes aqui. O pacote
contém capturas e relatório, sem afirmar conter os journals completos das fixtures.

Aceite restrito a este R1 offline: ticks separados por intervalo real, releitura da
policy, fim de orçamento ocioso, preservação da sessão interrompida e bloqueio no
restart, lock liberado e remoção da instalação de teste. Sem discovery/AUTH/FULL/POST
live, qualificação do principal do serviço, cancelamento de operação em andamento,
reconciliação de POST, recovery automático, rotação de journals ou prova multi-day.
Runtime v0.5e.6 e wrapper/policy/journal canônico v0.5f.0/schema v0.5f permanecem.

Próxima validação dentro do escopo do scheduler: soak estendido em fixture nova,
com o orçamento já existente --ticks 10 (primeiro ciclo >=9 minutos), preservando
os dois R1 aprovados. Esse ensaio ainda não foi executado e não qualifica multi-day.
