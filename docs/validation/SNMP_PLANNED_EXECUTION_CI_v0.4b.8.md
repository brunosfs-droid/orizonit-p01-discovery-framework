# SNMP v0.4b.8 — planejamento e execução qualificados no CI

Data: 05/10/2026 (-03). **CANDIDATE para dispositivos reais.**
Fonte qualificada: `b99806a1cc9623feb0fac660753ff2e8900f9c1d`.
Tree integral da fonte: `ff8315e787026d68bbf19de6357586056bef5668`.
Base: `1010a07d9a4bcb2db34a1baf2ab1777ff1484c24`.
[PR 122](https://github.com/brunosfs-droid/canca/pull/122).

## Evidência de execução

A fonte passou em **14 runs, 38 jobs e 186 etapas críticas**. Foram conferidos
os eventos esperados, matriz de jobs, head_sha, status/conclusion e timestamps
started_at/completed_at das etapas críticas. Steps condicionais de outro OS
não contam como execução. Logs de cada um dos doze jobs SNMP confirmaram
**26 casos do adapter + 28 da extensão, zero skips** em cada job.

| Workflow | PR run | Push run | Jobs no par |
| --- | --- | --- | --- |
| Read-only SNMP CI | [37294901741](https://github.com/brunosfs-droid/canca/actions/runs/37294901741) | [37294834916](https://github.com/brunosfs-droid/canca/actions/runs/37294834916) | 12 |
| Python CI | [37294901635](https://github.com/brunosfs-droid/canca/actions/runs/37294901635) | [37294834954](https://github.com/brunosfs-droid/canca/actions/runs/37294834954) | 2 |
| PostgreSQL CI | [37294901601](https://github.com/brunosfs-droid/canca/actions/runs/37294901601) | [37294835023](https://github.com/brunosfs-droid/canca/actions/runs/37294835023) | 4 |
| Operator Web CI | [37294901713](https://github.com/brunosfs-droid/canca/actions/runs/37294901713) | [37294834951](https://github.com/brunosfs-droid/canca/actions/runs/37294834951) | 2 |
| Operator Accounts CI | [37294901622](https://github.com/brunosfs-droid/canca/actions/runs/37294901622) | [37294835011](https://github.com/brunosfs-droid/canca/actions/runs/37294835011) | 8 |
| Optional Agent CI | [37294901619](https://github.com/brunosfs-droid/canca/actions/runs/37294901619) | [37294834984](https://github.com/brunosfs-droid/canca/actions/runs/37294834984) | 8 |
| JSON Parse Validation | [37294901730](https://github.com/brunosfs-droid/canca/actions/runs/37294901730) | [37294834959](https://github.com/brunosfs-droid/canca/actions/runs/37294834959) | 2 |

As 186 etapas compreendem cinco por job Python, quatro por PostgreSQL, uma por
Web, seis por contas, seis por agent (incluindo duas nativas do OS), cinco por
SNMP e uma por JSON. O workflow SNMP instala o runtime opcional e exige
CANCA_REQUIRE_SNMP_TESTS=1. Matriz Linux/Windows × Python 3.10/3.12/3.13.

## Contratos exercitados

| Contrato | Resultado sintético |
| --- | --- |
| Planner/CLI FULL v2c e v3 | Request de endpoint → plano JSON/SHA256 → executor CLI → oito GETs em ordem e oito campos; v3 recebido com model=3, level=3 |
| AUTH-only | Um sysObjectID, resultado access_probe_only |
| Shared credential stop | View negada no primeiro alvo suspende profile alias com as mesmas referências; agente do segundo alvo recebe zero requests; terceiro profile independente coleta oito campos |
| Falha parcial | Campo ausente preserva sete campos e sucesso do probe; outro alvo com a mesma credencial continua |
| Community incorreta | Timeout/silent denial, leitura não confirmada, segundo alvo suspenso, zero authentication budget consumed |
| Planejamento explícito | Nenhuma UDP observation inventada, profile escolhido sem prioridade/fallback; Unknown/taxonomy/realm/conflict/high-privilege gates mantidos |
| Autorização | Seed única, IPv4 literal unicast, limite de 25; manifest exige protocolo/scope autorizado e respeita exclusões |
| Drift | Referências, username, scope, v3 policy, contexto, autorização, endpoint e snapshot alterados bloqueiam antes de dispatch; validação repetida antes de carregar o adapter |
| Defaults/budgets | SNMP desligado sem opt-in, plano antigo bloqueado; duplicata/max_actions recusados antes de saída/rede |
| Evidência | Plano/job/targets JSON/SHA256, diretório novo e arquivos exclusivos; modos POSIX privados, inclusive jobs mistos; rótulo UTF-8 validado; exceções SNMP não copiam secret |

Os agentes escutam somente IPv4 loopback e contêm dados/credenciais sintéticos.
O fixture aceita IPs loopback distintos para demonstrar o freio multi-target;
seu default e os 26 casos anteriores continuam qualificados. O adapter
P01_SNMP_Enricher.py v0.4b.7 permanece byte a byte igual à base.

## Regressão e publicação

- Local: **54 casos SNMP / zero skips**, PASS em 6,968s. Suíte geral
  **609 casos / 134 skips**, 475 executados, PASS em 79,176s. Compile, 25 JSONs,
  schema/exemplo, 183 links relativos e diff checks passaram.
- Python CI: **609 casos / 134 skips** nos dois eventos, em 88,059s e 87,540s.
  Skips da suíte geral não substituem os testes obrigatórios do CI dedicado.
- PostgreSQL 16/17: **188 casos / zero skips por job**, em 26,167–33,811s.
  Transações e backup/restore/replay sintéticos passaram. Não há migração SQL.
- Chromium exerceu o fluxo real Web; contas/auditoria/revisão offline passaram
  em filesystem/HTTP nativos. Agent manteve lifecycle/intervalo/interrupção
  reais de systemd/SCM. Nenhum serviço foi instalado ou alterado no LAB.
- Credential Manager e portable mantêm suas fontes byte a byte iguais à base.
  Portable não fornece snmp_requests/enable_snmp, preservando o default desligado
  e a ausência de login Cancã. SSH/WinRM continuam na rota anterior; o envelope
  do executor identifica sua nova versão e é coberto pela regressão.
- Foram publicados os dezessete arquivos da fonte; tree integral local/remoto
  idêntico, incluindo arquivos/binários da base. Este registro e links de
  qualificação são uma revisão documental posterior, sem mudança de código.

## Limites

Não qualifica vendors/views/NAT reais, ACLs NTFS, autoria/assinatura, verdade
do inventário ou durabilidade do par JSON/sidecar contra queda de energia.
Não há fallback, SET, mapper, tabelas de interfaces/rotas ou expansão de scope.
summary.authentication_failures do job inclui leituras sem sucesso; a credencial
não é declarada inválida por timeout, e seu authentication failure budget fica
intacto. A redaction cobre os secrets resolvidos na tentativa, não quaisquer
outros dados confidenciais que um equipamento possa retornar.

Resolver/bundle/ingestão/findings e integração managed do portable ainda têm
incremento próprio. A cadeia SNMP end-to-end permanece pendente. Não há nova
validação manual solicitada; adiamento do LAB em 03/10 continua respeitado.
[Contrato/CLI](../SNMP_PLANNED_EXECUTION_v0.4b.8.md) e
[ADR 0034](../ADR_0034_Planned_SNMP_Execution_v0.4b.8.md).
