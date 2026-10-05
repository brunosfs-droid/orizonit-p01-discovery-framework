# Qualificação sintética SNMP evidence/portable — v0.4b.9

Data: 05/10/2026 (-03). **PASS no CI sintético da fonte.**
Operação em vendors/LAB reais: **CANDIDATE**, sem novo teste manual solicitado.

## Revisão qualificada

- Base: `e9250e12d53bb2e941c9e6bb888561166f69b94e`.
- Fonte: [`6a55039efad54b9746a11f0616bdddc449cf5fc0`](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/commit/6a55039efad54b9746a11f0616bdddc449cf5fc0).
- Árvore completa: `cbd60047f85a708988b3d2af6efd24d55580a28a`, idêntica a `git write-tree` e ao checkout remoto.
- [PR 123](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/123): 21 arquivos de implementação/contrato/tests/CI.
- Adapter `P01_SNMP_Enricher.py` v0.4b.7 intacto; defaults do scheduler,
  Web, contas, SQL e transporte mTLS preservados.

A fonte passou **14 runs / 38 jobs / 198 etapas críticas**. Conferidos os pares
push/pull_request dos sete workflows, nomes exatos da matriz, head_sha,
status/conclusion e timestamps de início/fim de cada etapa crítica. Etapas
skipped do outro OS não contam como qualificação. A publicação de arquivos foi
conferida pela árvore completa, incluindo assets binários preexistentes.

| Workflow | Jobs push + PR | Etapas críticas | Runs |
| --- | ---: | ---: | --- |
| Python CI | 2 | 10 | [pull_request](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088413) / [push](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049315) |
| JSON Parse Validation | 2 | 2 | [pull_request](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088285) / [push](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049256) |
| PostgreSQL CI | 4 | 16 | [pull_request](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088297) / [push](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049303) |
| Operator Web CI | 2 | 2 | [pull_request](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088473) / [push](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049391) |
| Operator Accounts CI | 8 | 48 | [pull_request](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088679) / [push](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049371) |
| Optional Agent CI | 8 | 48 | [pull_request](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088475) / [push](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049766) |
| Read-only SNMP CI | 12 | 72 | [pull_request](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088380) / [push](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049323) |

## SNMP sem skips

Cada job executou as três suites: **26 adapter + 28 planejamento/executor +
34 evidence/portable = 88 testes, zero skips**. Dependências opcionais são
obrigatórias nessa matriz. Logs confirmam contagem e conclusão efetiva.

| Evento | Matriz | Job | Adapter / plano / integração | Skips |
| --- | --- | --- | --- | ---: |
| pull_request | snmp-loopback (ubuntu-latest, 3.10) | [111756537332](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088380/job/111756537332) | 26 / 28 / 34 | 0 |
| pull_request | snmp-loopback (ubuntu-latest, 3.12) | [111756536969](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088380/job/111756536969) | 26 / 28 / 34 | 0 |
| pull_request | snmp-loopback (ubuntu-latest, 3.13) | [111756537418](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088380/job/111756537418) | 26 / 28 / 34 | 0 |
| pull_request | snmp-loopback (windows-latest, 3.10) | [111756537202](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088380/job/111756537202) | 26 / 28 / 34 | 0 |
| pull_request | snmp-loopback (windows-latest, 3.12) | [111756537414](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088380/job/111756537414) | 26 / 28 / 34 | 0 |
| pull_request | snmp-loopback (windows-latest, 3.13) | [111756537231](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308088380/job/111756537231) | 26 / 28 / 34 | 0 |
| push | snmp-loopback (ubuntu-latest, 3.10) | [111756407493](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049323/job/111756407493) | 26 / 28 / 34 | 0 |
| push | snmp-loopback (ubuntu-latest, 3.12) | [111756407342](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049323/job/111756407342) | 26 / 28 / 34 | 0 |
| push | snmp-loopback (ubuntu-latest, 3.13) | [111756407421](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049323/job/111756407421) | 26 / 28 / 34 | 0 |
| push | snmp-loopback (windows-latest, 3.10) | [111756407147](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049323/job/111756407147) | 26 / 28 / 34 | 0 |
| push | snmp-loopback (windows-latest, 3.12) | [111756407424](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049323/job/111756407424) | 26 / 28 / 34 | 0 |
| push | snmp-loopback (windows-latest, 3.13) | [111756407335](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37308049323/job/111756407335) | 26 / 28 / 34 | 0 |

Os seis casos de integração com agente real cobrem v2c FULL, v3 authPriv FULL,
FULL parcial exportável, AUTH falho/retry explícito com nova saída, drift após
AUTH e CLI real. Somente IPv4 loopback, UDP/USM/criptografia e credenciais
sintéticas. Prévia não usa provider/rede; AUTH lê um OID e FULL até oito.

Casos puros verificam envelopes, OIDs/ordem, tipos/limites, contagens,
diagnósticos, sysObjectID não único, sysName corroborado, hints sem promoção,
realm sem promoção por SNMP, uptime, bytes duplicados e arquivos privados.
Bundle conserva bytes/SHA; contratos malformados são rejeitados mesmo após
rehash do inventário. Replay rejeita adulteração de claims, fontes, cobertura,
extensão e correlação do edge. Processo isolado de import confirma ausência
de adapter, credential manager e PySNMP carregados.

## Regressão e controles preservados

Python CI: **643 casos / 140 skips esperados**, tanto push quanto PR. As omissões
são de runtime opcional, OS nativo ou PostgreSQL indisponível nessa suite;
SNMP tem qualificação separada sem skips. Os quatro jobs PostgreSQL 16/17
executaram **188 casos sem skips** e a qualificação de backup/restore.
Chromium, revisões de contas/scrypt, auditoria e serviços SCM/systemd passaram.
Etapas nativas incluem lifecycle/crash review e intervalo/interrupção reais
no OS correspondente.

Local: 88 SNMP sem skips (11.812s); regressão 643 PASS/140 skips (93.128s);
113 arquivos Python compilados e 25 JSONs válidos. Links relativos conferidos.

A primeira regressão local mostrou `export_busy` no teste preexistente de slot
compartilhado de export Web. A suite isolada passou (9 casos, 9.154s), a repetição
geral passou e os dois jobs Python CI passaram sem alterar código Web ou esse
teste. Não há falha de qualificação em aberto na fonte registrada.

## Fechamento e limites

A atualização deste registro/ADR/contrato é somente documental e tem CI próprio
no head final da PR; a prova acima permanece ligada ao SHA da fonte.
A integração exige repetir a conferência do head final, sem reaproveitar apenas
o status da fonte anterior.

Essa qualificação não comprova vendors/views/NAT reais, ACL NTFS, identidade
criptográfica de origem ou inventário verdadeiro. SHA256 detecta inconsistência
e drift; não é assinatura. SNMPv2c continua sem criptografia. Windows depende
de parent com ACL privada. Nenhuma conta, serviço instalado ou alvo de cliente
foi alterado; agentes de CI são fixtures isoladas.

[Contrato](../SNMP_EVIDENCE_PORTABLE_v0.4b.9.md) ·
[ADR](../ADR_0035_SNMP_Evidence_and_Portable_v0.4b.9.md).
