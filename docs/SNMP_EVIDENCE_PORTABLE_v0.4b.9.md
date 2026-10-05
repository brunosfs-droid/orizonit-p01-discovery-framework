# Evidência SNMP e portable — v0.4b.9

Atualizado em 05/10/2026 (-03). **CANDIDATE para dispositivos reais.**
Classificação A — MVP. Nenhum teste manual de LAB solicitado neste incremento.

A coleta SNMP passa a percorrer o portable gerenciado, resolver, bundle e replay
offline. O adapter v0.4b.7, seus oito GETs e o contrato de requests/plano v0.4b.8
permanecem preservados. O collector portable continua sem login Cancã;
credenciais dos alvos usam o Secret Provider existente. Login Web e identidade
mTLS do node permanecem separados.

| Componente | Versão deste incremento | Contrato preservado |
| --- | --- | --- |
| Leitor puro SNMP | 0.4b.9 | Standalone 0.4b.7 / target do executor 0.4b.8 |
| Asset Resolver | 0.4c.1 | Schema 0.4c com diagnósticos opcionais |
| Evidence Bundle | 0.5a.1 | Formato e roles 0.5a |
| Offline Import | 0.5b.1 | Receipt 0.5b |
| Portable | 0.5e.7 | Estado 0.5e / fluxo em etapas |

## Identidade e proveniência

`sysObjectID` descreve produto/modelo e pode repetir em vários equipamentos.
Não é serial, UUID nem identificador forte. O resolver não extrai serial/vendor,
versão de OS ou associação AD de sysDescr. Hints de hostname/tipo/OS/realm do
plano não viram fatos SNMP coletados.

Somente um sysName remoto com formato de hostname utilizável participa da
correlação. Ele precisa de namespace correspondente e evidência independente de
IP/MAC num cluster originado pelo discovery. IP isolado, modelo compartilhado,
nome ausente, endereço como nome ou texto redigido não causam merge. Um sysName
com suffix de domínio também não promove realm AD pelo manifest. Observação
SNMP não correlacionada recebe anchor próprio; fontes de bytes idênticos são
deduplicadas. IDs continuam sem registry persistente entre assessments.

Valores válidos ficam em `assets[].field_provenance["snmp.<campo>"]`, com
strength=observed, source_id ligado ao SHA256 da fonte e evidence=snmp_get_oid:OID.
sysName utilizável também gera claims observados de hostname/FQDN. Uptime variável
mantém todas as claims sem conflito de configuração; outros valores contraditórios
continuam em conflicts. Serviço SNMP confirmado conserva a porta UDP efetiva.

`inputs.snmp_evidence[]` mantém fonte/SHA, modo, acesso, estado, limites,
contagens e cobertura por campo, sem valores de credenciais ou suas referências.
Summary acrescenta snmp_evidence_seen, snmp_inventory_observations e
snmp_diagnostic_observations somente quando há SNMP.

AUTH-only, dry-run, secret indisponível, dispatch falho e probe sem confirmação
permanecem diagnósticos, sem criar/promover inventário. FULL com acesso confirmado
preserva campos disponíveis e os estados ausentes/erro. O leitor valida campos,
ordem/OIDs, tipos, limites, cobertura e contagens; SNMP reconhecido inválido é
rejeitado antes da rota genérica. Referências de providers não entram em texto
coletado. O leitor e o replay não importam adapter, credential manager ou PySNMP.

## Bundle e replay

O bundle conserva JSON bruto, SHA256, roles existentes e sidecars. Criação e
validação rejeitam contratos SNMP malformados mesmo quando o inventário de hashes
foi recalculado. SHA256 demonstra consistência, não autentica autoria.

No modo process, o importer refaz o resolver usando somente arquivos do bundle.
A comparação com o resolver edge inclui claims/OIDs/fontes SNMP, cobertura,
diagnósticos, contagens e correlações. Alterar esses campos apenas no resultado
embarcado bloqueia o processamento. A projeção dos fluxos sem SNMP é preservada.
Se um agente autorizado substituir todas as evidências e recalcular hashes,
essa comparação não fornece autenticidade criptográfica.

## Portable gerenciado

O manifest deve autorizar SNMP, e cada endpoint deve corresponder a uma seed
única, scope/protocolo permitido e profile elegível. Não há descoberta UDP
inventada, fallback, expansão ou escolha automática de credencial.

Depois do discovery, informe `--snmp-requests` ao comando run que executa o
planejamento. O portable registra caminho e hash dos bytes do request, manifest
e profiles; alterações posteriores bloqueiam prévia/acesso. Conteúdo do provider
é consultado na tentativa, sem persistir valores. Cada invocação avança uma etapa.

Referência PowerShell para entradas já preparadas e autorizadas:

```powershell
# Planejamento, depois de network_discovery: completed
python .\runtime\P01_Discovery_Node.py run --workspace C:\P01\runs\ASSESS\RUN `
  --snmp-requests C:\P01\inputs\snmp-requests.json

# Prévia sem rede/Secret Provider
python .\runtime\P01_Discovery_Node.py run --workspace C:\P01\runs\ASSESS\RUN --enable-snmp

# Um probe de acesso por alvo, depois de revisar a prévia
python .\runtime\P01_Discovery_Node.py run --workspace C:\P01\runs\ASSESS\RUN `
  --enable-snmp --execute --auth-only --ack-authorized-access

# Até oito GETs por alvo, somente após AUTH validado
python .\runtime\P01_Discovery_Node.py run --workspace C:\P01\runs\ASSESS\RUN `
  --enable-snmp --execute --full-enrichment --ack-authorized-access

# Resolver offline e bundle dos targets FULL registrados
python .\runtime\P01_Discovery_Node.py run --workspace C:\P01\runs\ASSESS\RUN
python .\runtime\P01_Discovery_Node.py export --workspace C:\P01\runs\ASSESS\RUN
```

`--enable-snmp` é obrigatório em prévia, AUTH e FULL quando o plano inclui SNMP.
O opt-in anterior precisa estar ligado à evidência da etapa anterior. Uma prévia
com ações bloqueadas não autoriza AUTH. O scheduler não fornece esse opt-in;
default permanece desligado. Nenhuma conta Cancã é exigida para executar.

Planos e tentativas SNMP usam subdiretórios novos e privados. Retomada de etapa
concluída devolve o artefato existente antes de consultar os inputs ou rede.
AUTH parcial/falho bloqueia FULL e repetição implícita. Retry de falha continua
exigindo flag própria, autorização e enable-snmp; preserva evidências anteriores
em diretório diferente. Replanejamento após prévia/acesso SNMP exige novo workspace.

FULL SNMP com probe confirmado e campos parciais permite resolver/export.
`artifacts.credentialed_execution_full.snmp_partial_targets` contabiliza esses
alvos; collected significa alvo com inventário elegível, não oito campos completos.
Consulte coverage/collected_fields para a completude. Gates legados SSH/WinRM
permanecem. Export inclui somente targets FULL registrados, sem misturar AUTH.

## Qualificação e limites

Fonte qualificada no CI: 14 runs / 38 jobs / 198 etapas críticas; 88 testes SNMP
sem skips em cada job da matriz. A operação em dispositivos reais permanece CANDIDATE.

Testes sintéticos exercitam contratos, identidade negativa, adulteração, drift,
resume e a cadeia com UDP v2c/v3 authPriv reais. CI requer dependências opcionais
e executa em Linux/Windows × Python 3.10/3.12/3.13. Regressão default continua
sem requerer runtime SNMP. [Registro de qualificação](validation/SNMP_EVIDENCE_PORTABLE_CI_v0.4b.9.md).

Vendors/views/NAT reais e LAB permanecem pendentes. Windows depende de ACL
privada do parent; modos POSIX não comprovam NTFS. Não acrescenta SET, tabelas de
interfaces, LLDP/CDP, mapper, findings, AD login, scheduler ou alterações Web/SQL.
SNMPv2c permanece sem criptografia. Par JSON/sidecar exclusivo não promete
atomicidade frente a queda de energia.

[ADR 0035](ADR_0035_SNMP_Evidence_and_Portable_v0.4b.9.md) ·
[Planejamento e executor](SNMP_PLANNED_EXECUTION_v0.4b.8.md) ·
[Adapter](../credentialed_enrichment/README-SNMP.md).
