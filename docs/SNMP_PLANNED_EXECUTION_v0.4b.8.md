# Planejamento e execução SNMP — v0.4b.8

Atualizado em 05/10/2026 (-03). **CANDIDATE para operação em dispositivos reais.**
Classificação A — MVP. Não há novo teste manual solicitado neste incremento.

O planner passa a produzir ações SNMP revisáveis; o executor pode executá-las
com habilitação explícita. O adapter [v0.4b.7](../credentialed_enrichment/README-SNMP.md)
é reutilizado sem alteração. Collector portable continua sem login Cancã.
Credenciais de alvos, autenticação Web e identidade mTLS do node têm finalidades
separadas. A integração managed do portable e de evidências segue na
[extensão v0.4b.9](SNMP_EVIDENCE_PORTABLE_v0.4b.9.md).

## Endpoints declarados

O scanner atual observa TCP, não prova disponibilidade de SNMP por UDP. Portanto,
`--snmp-requests` recebe um arquivo com até 25 endpoints explícitos; nunca extrai
SNMP de uma porta TCP ou tenta todos os profiles armazenados.

```json
{
  "schema_version": "0.4b.8",
  "endpoints": [
    {"target_ip": "192.0.2.10", "port": 161, "profile_id": "network-snmpv3-read"}
  ]
}
```

Cada IPv4 literal unicast deve existir exatamente uma vez nas seeds do discovery.
Um IP aparece no máximo uma vez; não há ranges, DNS, expansão, pivot ou seleção
de profile por prioridade. A porta é UDP, inteira entre 1 e 65535. O leitor do
arquivo limita entrada a 64 KiB e rejeita chaves duplicadas e NaN/Infinity.
[Schema](../schemas/p01-snmp-requests-schema-v0.4b.8.json) e
[exemplo](../orchestrator/snmp.requests.example.json).

Com `--manifest`, SNMP precisa constar em allowed_protocols; endpoint deve
pertencer a authorized_scopes e ficar fora de exclude_scopes. Sem manifest,
a declaração delimita autorização de SNMP àquele IP /32. Em ambos os casos,
scope e selectors do profile continuam gates independentes.

O contexto usa os campos da seed e do manifest, com `services: ["snmp"]` declarado
pelo operador. Unknown, taxonomy, realm/evidência e conflitos não são promovidos
por esse hint. O plano mantém `detected_protocols` e summary.protocols somente
para SSH/WinRM observados; SNMP registra endpoint.source=operator_declared.
Profile inabilitado, incompatível ou ausente produz motivo de inelegibilidade,
sem fallback para outro profile.

## Profile e revisão

Use o Credential Manager/Secret Provider existente. O
[exemplo de profiles](../credential_manager/credentials.snmp.example.json)
permanece desabilitado; ajustar metadados, scopes e habilitação é uma ação
explícita do operador quando houver autorização. Valores de community/chaves
nunca são argumentos de CLI nem campos do request ou do plano.

v3 exige username e authPriv SHA-256/AES-128; v2c exige community reference e
continua transmitindo a comunidade sem criptografia. Não há downgrade/retries.
O plano liga configuração completa do profile, inclusive referências sem seus
valores, contexto derivado, endpoint e política de autorização por SHA256
canônico. Copia somente a visão pública do profile, sem locators de secrets.
Executor revalida esses bindings no preflight e novamente no dispatch, antes de
resolver credenciais. Troca de valor no mesmo provider reference não muda o
binding: o provider é consultado a cada tentativa.

## Referência de CLI

Os caminhos abaixo representam entradas já preparadas e autorizadas; não são
uma solicitação de executar teste de LAB agora. Os diretórios de saída devem
ser novos, com parent existente e privado. Windows depende da ACL desse parent;
este incremento não provisiona ACLs NTFS.

```powershell
python .\orchestrator\P01_Credentialed_Discovery_Planner.py `
  --discovery C:\P01\inputs\discovery.json `
  --profiles C:\P01\inputs\profiles.json `
  --snmp-requests C:\P01\inputs\snmp-requests.json `
  --manifest C:\P01\inputs\assessment-manifest.json `
  --run-label SNMP-PLAN `
  --output-dir C:\P01\output\snmp-plan-new
```

O JSON/SHA256 resultante deve ser revisado. Para conferir elegibilidade sem
credenciais ou rede:

```powershell
python .\orchestrator\P01_Credentialed_Discovery_Executor.py `
  --plan C:\P01\inputs\reviewed-plan.json `
  --plan-sha256 C:\P01\inputs\reviewed-plan.json.sha256 `
  --profiles C:\P01\inputs\profiles.json `
  --enable-snmp `
  --output-dir C:\P01\output\snmp-dry-new
```

Execução requer também `--execute --ack-authorized-access` e o sidecar do plano.
`--auth-only` conserva somente o sysObjectID access probe. Sem AUTH-only,
FULL tenta até oito GETs numéricos fixos, timeout 2s, deadline de troca 20s por
alvo e retries zero. O prazo não cobre Secret Provider nem escrita de arquivos;
SNMPv3 discovery/reports podem usar datagramas adicionais.

SNMP fica desligado sem `--enable-snmp`, mesmo que o plano contenha ações novas.
API run_job tem enable_snmp=false por default; o portable mantém esse default.
Planos antigos/incompletos, drift e contexto incompatível bloqueiam a ação.
Duplicatas, mais de 25 endpoints ou excesso de max_actions rejeitam o job
antes de providers/dispatch. Não existe login Cancã neste fluxo.

## Resultado e freio por credencial

| Campo | Significado |
| --- | --- |
| action.protocol / endpoint_source | snmp / operator_declared |
| authentication.success | Leitura do probe confirmada; v2c não autentica a identidade do equipamento |
| enrichment.adapter_version / schema_version | 0.4b.7, contrato preservado do adapter |
| enrichment.collection_status | collected, collected_with_field_failures, access_probe_only ou not_collected |
| enrichment.fields | OID, status e valor validado por campo; remote text passa pela redaction do adapter |
| enrichment.summary | get_operations_attempted e collected_fields |
| metadata.plan_sha256 | Bytes do plano revisado ligados ao resultado |
| summary.snmp_unconfirmed_credential_circuits | Identidades de referências com leitura não confirmada neste job |

Uma leitura não confirmada suspende os próximos endpoints SNMP que compartilham
as mesmas referências, inclusive profiles com IDs diferentes. Profile com
referências independentes continua. Esse freio não declara senha inválida nem
consome credential_circuits.authentication_failures. FULL parcial com probe
bem-sucedido conserva a credencial elegível para o próximo alvo.

summary.authentication_failures mantém a semântica anterior do executor:
tentativas concluídas sem sucesso, inclusive falha ambígua. Não use esse total
como diagnóstico de senha inválida. Consulte o circuito, failure_category e
coverage. Exit 0 do executor significa job produzido; ações podem estar
bloqueadas/skipped ou ter leitura não confirmada. Isso difere do exit 3 do
adapter independente e preserva a compatibilidade do executor.

Saída habilitada com ações SNMP exige um diretório novo antes de qualquer
dispatch. Todos os targets desse job e o job principal usam criação exclusiva,
JSON/SHA256 e modos POSIX 0600, dentro de diretórios 0700. Planos com extensão
SNMP também usam esse modo privado. Uma falha de escrita não confirma conclusão;
não há garantia de atomicidade do par JSON/sidecar contra queda de energia.

## Qualificação e limites

CI exige runtime opcional instalado e executa os testes do adapter e da extensão
em Linux/Windows × Python 3.10/3.12/3.13. Fixtures usam apenas agentes IPv4
loopback com dados e credenciais sintéticos. Cobrem CLI real v2c/v3, AUTH-only,
partial, shared-credential stop, continuidade independente, autorização, drift,
defaults, SHA256 e privacidade/exclusividade dos arquivos.

SHA256 detecta drift, não autoria, inventário verdadeiro ou autorização externa.
Não qualifica vendors/views/NAT reais nem ACLs NTFS. Integração
resolver/bundle/ingestão e controles managed do portable têm contrato/qualificação
próprios em [v0.4b.9](SNMP_EVIDENCE_PORTABLE_v0.4b.9.md); findings permanecem posteriores. Não há tabelas de interfaces/rotas, LLDP/CDP, mapper, AD login,
SET ou execução remota arbitrária. A cadeia SNMP end-to-end pertence ao incremento v0.4b.9.
[ADR 0034](ADR_0034_Planned_SNMP_Execution_v0.4b.8.md).
[Qualificação sintética da fonte](validation/SNMP_PLANNED_EXECUTION_CI_v0.4b.8.md):
14 runs / 38 jobs, 28 casos novos e 26 do adapter sem skips em cada job SNMP.
