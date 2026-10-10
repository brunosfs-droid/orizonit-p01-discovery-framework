# SNMP v0.4b.7 — qualificação sintética independente do LAB

Data: 04/10/2026 (-03). **CANDIDATE para dispositivos reais.**
Fonte qualificada: `c3402e544c60303eb1d227c0e3828b883c2414d6`.
Tree integral: `d4b1c1e1a523a5640e41785ec9723ed68bb2bbf2`.
Base: `399bc5021ca81d8a9537e846068c0f49a2292b8b`.
[PR #121](https://github.com/brunosfs-droid/canca/pull/121)
· [ADR 0033](../ADR_0033_Read_Only_SNMP_v0.4b.7.md)
· [Contrato e uso](../../credentialed_enrichment/README-SNMP.md).

## Resultado e alcance

Treze runs / **37 jobs PASS**, no head exato acima, com **173 etapas críticas
realmente executadas**. Foram conferidos status/conclusion, matriz esperada,
head_sha dos jobs e started_at/completed_at preenchidos de cada etapa crítica.
Steps condicionais do outro sistema operacional não contam como execução.
Não houve execução em equipamento, conta, serviço ou base real do mantenedor.
Nenhum novo passo manual solicitado; o adiamento do LAB continua respeitado.

| Workflow | PR run | Push run | Jobs no par |
| --- | --- | --- | --- |
| Read-only SNMP CI | [37211337082](https://github.com/brunosfs-droid/canca/actions/runs/37211337082) | [37211333884](https://github.com/brunosfs-droid/canca/actions/runs/37211333884) | 12 |
| Python CI | [37211336986](https://github.com/brunosfs-droid/canca/actions/runs/37211336986) | [37211333883](https://github.com/brunosfs-droid/canca/actions/runs/37211333883) | 2 |
| PostgreSQL CI | [37211336912](https://github.com/brunosfs-droid/canca/actions/runs/37211336912) | [37211333906](https://github.com/brunosfs-droid/canca/actions/runs/37211333906) | 4 |
| Operator Web CI | [37211337060](https://github.com/brunosfs-droid/canca/actions/runs/37211337060) | [37211333901](https://github.com/brunosfs-droid/canca/actions/runs/37211333901) | 2 |
| Operator Accounts CI | [37211336886](https://github.com/brunosfs-droid/canca/actions/runs/37211336886) | [37211333987](https://github.com/brunosfs-droid/canca/actions/runs/37211333987) | 8 |
| Optional Agent CI | [37211336858](https://github.com/brunosfs-droid/canca/actions/runs/37211336858) | [37211333926](https://github.com/brunosfs-droid/canca/actions/runs/37211333926) | 8 |
| JSON Parse Validation | [37211336958](https://github.com/brunosfs-droid/canca/actions/runs/37211336958) | Não acionado: este push altera apenas Python | 1 |

## Protocolo e contrato novos

Cada um dos doze jobs SNMP executou **26 casos, zero skips**, com dependências
opcionais instaladas e CANCA_REQUIRE_SNMP_TESTS=1. Matriz Linux/Windows × Python
3.10/3.12/3.13, nos eventos push e PR. O workflow valida instalação, compilação,
casos reais e schemas/exemplos desabilitados, quatro etapas críticas por job.

| Caso | Evidência sintética |
| --- | --- |
| FULL v2c/v3 | Oito GETs numéricos recebidos em ordem, oito campos tipados; dados fixos de router sintético |
| SNMPv3 authPriv | Agente recebeu securityModel=3, securityLevel=3; criptografia SHA-256/AES-128 real e sem texto de secrets nos datagramas observados |
| SNMPv2c explícito | Agente recebeu model=2, level=1; comunidade presente no transporte, warning na evidência, nenhum fallback |
| Credenciais UTF-8 | Probe v2c/v3 com comunidade/chaves/username acentuados, passados como bytes UTF-8 explícitos |
| AUTH-only | Um sysObjectID; estado access_probe_only, nunca FULL |
| Campo inexistente | sysLocation not_available, sete campos preservados, FULL parcial |
| View negada | Probe access_denied, zero leitura confirmada, nenhum GET posterior |
| Community/chave incorreta | Zero acesso ao handler do agente, um GET lógico, sem downgrade/profile alternativo ou penalização por timeout |
| Scope/protocolo/contexto/config | IPv4 literal, perfil habilitado/ID explícito, selectors e política v3 antes de provider/cliente |
| Tipo/OID/tamanho | Rejeição de OID divergente, quantidade errada de bindings, tag ASN.1 incompatível, UTF-8 inválido e valor grande/fora do intervalo |
| Deadline e falhas locais | Cliente lento limitado, close executado; exceções de cliente/provider não copiadas para output |
| Saída | JSON validado pelo schema, arquivos exclusivos/SHA256, modos POSIX privados e redaction de secrets resolvidos em texto remoto |

A fonte inicial `4b869cdd2bea0500addd90bb991f3d674b54d6d4` cobria 25 casos.
A revisão qualificada acrescenta o caso UTF-8 e codificação explícita; resultados
do head inicial não substituem a qualificação do head c3402e5.
A validação ASN.1 usa tagSet: o decoder real devolve ObjectIdentifier da base
pyasn1 em vez da subclass construída manualmente. Aceitar só a classe Python
falharia no probe real; a tag exata do protocolo continua obrigatória.

## Regressão e preservação

- Local: 26 casos SNMP sem skips em 2,490s; suíte geral **581 casos / 128 skips**,
  453 executados, PASS em 78,917s. Os dez casos sem runtime SNMP são executados
  na suíte geral; os outros dezesseis usam a matriz dedicada com zero skips.
  Compile, JSON/schema/exemplos, links relativos e diff checks passaram.
- Python CI: 581 casos / 128 skips nos dois eventos. PostgreSQL **188 casos,
  zero skips por job**, em 16.15/17.11; backup/restore sintético e replay passaram.
- Chromium continua exercitando login, seleção, preview/download/logout e
  auditoria privada nas telas reais. Nenhuma nova alteração visual foi feita.
  Este registro não afirma identidade de pixels ou de ZIPs gerados neste run.
- Contas/auditoria/revisão offline permanecem verificadas em filesystem/HTTP
  nativos. Agent mantém contratos de policy/journal/lock, interrupção/tamper e
  lifecycle/intervalo reais de systemd/SCM. Não há instalação no LAB.
- Dezessete fontes anteriores foram comparadas byte a byte com a base: portable,
  planner, executor, Credential Manager, SSH/WinRM, resolver, bundle, offline
  importer, Auth/API/Web/Audit/Audit_Check e três módulos canônicos de relatório.
  Nenhum formato de relatório, guia/pin de LAB ou migração de banco foi alterado.
- Publicação conferiu os dezesseis arquivos de fonte e a igualdade do tree Git
  integral local/remoto, incluindo os demais arquivos e binários da base.

As 173 etapas compreendem cinco por job Python, quatro por PostgreSQL, uma por
Web, seis por contas, seis por agent (incluindo duas próprias do OS), quatro por
SNMP e uma de JSON. Conclusão agregada verde, step ausente ou skipped isolado
não foi usado como prova de uma etapa crítica.

## Limites

Não comprova vendors, views reais, NAT, compatibilidade com versões diferentes,
ACLs NTFS, durabilidade contra queda de energia, assinatura/autoria ou operação
de produção. v2c não autentica a identidade do equipamento; timeout não identifica
credencial inválida. A redaction conhece somente os secrets resolvidos nesta
tentativa, não outros valores confidenciais que um agente possa expor.

Sem tabelas de interfaces/rotas/LLDP/CDP, mapper, scan/expansão, SET, execução
remota arbitrária, tenancy/RBAC, integração AD, ou integração automática com
planner/executor/portable/resolver/bundle/ingestão/findings. Esse adapter entrega
um primeiro componente do SNMP essencial do MVP; não declara a cadeia SNMP
end-to-end pronta. Collector portable continua sem login Cancã.
