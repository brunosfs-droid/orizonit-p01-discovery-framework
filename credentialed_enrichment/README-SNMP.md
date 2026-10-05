# Enriquecimento SNMP — v0.4b.7

Adapter **CANDIDATE**, independente, de alvo único IPv4. Coleta informações
básicas por GET e não exige login Cancã. Credenciais de equipamento permanecem
nos Secret Providers existentes. Autenticação do servidor Web é uma fronteira
separada. Nenhum novo teste manual solicitado em 04/10/2026 (-03).

## Instalação opcional

Use um ambiente Python isolado. Dry-run funciona sem estas dependências:

```powershell
python -m pip install -r .\credentialed_enrichment\requirements-snmp.txt
```

O CI qualifica Python 3.10/3.12/3.13 em Linux e Windows, com agentes sintéticos
loopback. Isso não qualifica compatibilidade com equipamentos/vendors do LAB.

## Profile e credenciais

Copie [credentials.snmp.example.json](../credential_manager/credentials.snmp.example.json)
para um arquivo local fora do Git, restrinja o scope e só habilite o profile após
autorização. Exemplos vêm **desabilitados**. Escolha um único profile ID:

| auth_type | Metadados | secret_refs obrigatórias |
| --- | --- | --- |
| snmpv3 | username; snmp_security exato: authPriv / sha256 / aes128 | auth_key, priv_key |
| snmpv2c | Sem snmp_security | community |

SNMPv3 usa SHA-256 (HMAC-SHA-256-192) e AES-128. Não há fallback para SHA-1/MD5,
DES, authNoPriv, noAuthNoPriv ou v2c. Outro algoritmo exige incremento próprio.
SNMPv2c transmite a comunidade sem criptografia; uso legado explicitamente
selecionado, sem tentativa da comunidade `public` ou outra comunidade padrão.

Use [store-wincred](../credential_manager/README.md#store-wincred) para armazenar
cada chave/community com entrada oculta. `env://` e `prompt://` também são
suportados. Nunca coloque valores de segredo na CLI, em profiles ou no contexto.
Chaves v3 exigem 8–255 bytes UTF-8; community exige 1–255 bytes.

O contexto JSON é fornecido pelo operador, conforme os selectors do profile:

```json
{"device_type":"Router/Gateway","services":["snmp"],"confidence":"Low"}
```

Esses valores são hints explícitos, não nova evidência de descoberta. O scanner
TCP não comprova UDP/161. Contexto ausente fica Unknown: exige allow_unknown
explícito e continua sujeito aos demais selectors e gates de realm. Perfis rich
mantêm as exigências de realm/target/privilege atuais; uma declaração não promove
AD para observed. Nenhum profile alternativo é tentado.

## Dry-run e execução autorizada

O diretório de saída deve ser novo, com parent existente. O comando abaixo
valida profile, protocolo, IPv4, scope e contexto, sem resolver secrets ou abrir
sockets, e grava `snmp.json` / `snmp.json.sha256`:

```powershell
python .\credentialed_enrichment\P01_SNMP_Enricher.py `
  --profiles .\credentials.local.json --profile-id network-snmpv3-read `
  --context .\snmp-context.local.json --target 192.0.2.10 `
  --output-dir .\output\snmp-dry
```

Em ambiente autorizado, `--execute --ack-authorized-access --auth-only` acrescenta
somente o probe sysObjectID. `--execute --ack-authorized-access` faz FULL.
Cada comando usa um diretório novo. Não há login do programa, scan de subnets,
autorização implícita ou execução remota arbitrária.

| Campo | OID | Valor |
| --- | --- | --- |
| sys_object_id | 1.3.6.1.2.1.1.2.0 | OID do tipo de equipamento; probe |
| sys_description | 1.3.6.1.2.1.1.1.0 | Descrição UTF-8 |
| sys_uptime_ticks | 1.3.6.1.2.1.1.3.0 | TimeTicks em centésimos de segundo |
| sys_name | 1.3.6.1.2.1.1.5.0 | Nome informado pelo agente |
| sys_location | 1.3.6.1.2.1.1.6.0 | Local informado pelo agente |
| sys_services | 1.3.6.1.2.1.1.7.0 | Bitmask de camadas, 0–127 |
| interface_count | 1.3.6.1.2.1.2.1.0 | Quantidade informada de interfaces |
| ipv4_forwarding | 1.3.6.1.2.1.4.1.0 | 1=forwarding; 2=not-forwarding |

Não coleta tabelas de interfaces, rotas, LLDP/CDP, topology, traps ou sysContact.
sysName/sysObjectID não são identificadores únicos de asset; não alimentam
correlação automática neste incremento.

## Limites e interpretação

- Uma tentativa de profile, até oito GETs lógicos (um em AUTH-only), retries de
  aplicação zero. Descoberta/sincronização de engine v3 pode gerar mensagens
  adicionais da biblioteca. Não há orçamento prometido de oito datagramas.
- `--port` default 161 (1–65535), `--timeout` default 2s (0,1–5), `--deadline`
  default 20s (0,1–45). O prazo global inclui abertura do cliente e consultas;
  não inclui prompt/Secret Provider, serialização ou escrita local.
- Resposta só é aceita para o OID exato e tag ASN.1 esperada. Texto remoto até
  1024 bytes, UTF-8 válido; valores inválidos/ausentes/grandes têm estado próprio.
- Probe negado/sem resposta encerra a coleta. Falha posterior de campo conserva
  os demais; timeout/erro de canal interrompe os GETs restantes. Estados
  not_attempted/deadline_exceeded nunca representam ausência comprovada do campo.
- Timeout pode significar transporte, view, filtro ou community incorreta;
  `transport_or_silent_denial` não consome orçamento de credencial. Erro USM
  também não é integrado a circuit breaker compartilhado neste adapter separado.
- `authentication.success` significa leitura confirmada pelo probe. Em v2c
  não prova identidade autenticada do dispositivo. AUTH-only não é FULL.
- Erros não copiam exceções/providers/biblioteca. Secrets resolvidos são redigidos
  por correspondência literal nos textos remotos; valores numéricos/OIDs que
  coincidem são omitidos. Isso não identifica outros segredos desconhecidos que
  um agente possa indevidamente retornar. Evidência é confidencial.
- Diretório novo 0700 e arquivos novos 0600 em POSIX, sem sobrescrita. No Windows,
  use parent com ACL privada; esta versão não provisiona/qualifica ACLs NTFS.
  SHA256 detecta divergência de bytes, não é assinatura nem prova de autoria.

Exit 0: dry-run elegível ou probe bem-sucedido, inclusive FULL parcial. Exit 3:
execução sem leitura confirmada (inclusive secret indisponível). Exit 2:
argumentos/entrada/saída inválidos. Verifique collection.status e a cobertura
de campos; exit 0 isolado não prova coleta completa.

Formato: [schema](../schemas/p01-snmp-enrichment-schema-v0.4b.7.json).
Decisão: [ADR 0033](../docs/ADR_0033_Read_Only_SNMP_v0.4b.7.md).
Planejamento e execução explícitos são acrescentados pela
[extensão v0.4b.8](../docs/SNMP_PLANNED_EXECUTION_v0.4b.8.md), sem alterar este
adapter ou seu contrato. SNMP continua default off; portable managed, resolver,
bundle, ingestão e findings seguem para incremento posterior. Nenhuma conta,
serviço ou target real foi modificado.
