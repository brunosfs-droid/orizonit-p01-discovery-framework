# P01 Network Discovery — Roadmap v0.4

## v0.4a — Network Discovery MVP

- múltiplos CIDRs/faixas;
- exclusões;
- guardrail para scopes grandes;
- ICMP + ARP local + TCP connect;
- reverse DNS;
- banners básicos;
- HTTP/HTTPS fingerprint;
- SSDP/UPnP;
- device/OS guess com confidence;
- JSON + SHA256;
- zero credenciais.

## v0.4b — Credentialed Enrichment

### v0.4b.1 — Credential Manager Foundation
- Credential Profile sem segredo em arquivo;
- Secret Provider abstraction;
- prioridade e escopo por credencial;
- tentativas limitadas e lockout protection;
- nenhum segredo em JSON/log.
- **Status:** LAB VALIDATED no Windows.

### v0.4b.2 — SSH Enrichment
- password auth usando Secret Provider;
- TOFU/strict host key policy;
- allowlist fixa de comandos read-only;
- hostname/kernel/platform;
- interfaces, routes e IPv4 forwarding;
- candidate networks sem scan automático;
- JSON + SHA256.
- **Status:** autenticação real validada contra Dropbear; o equipamento de teste aceitou SSH, mas não devolveu output no canal exec. v0.4b.2.1 passa a classificar explicitamente esse caso como `authenticated_no_exec_output`. Coleta completa foi validada em Ubuntu e Rocky através do P01-MGMT01, com hostname, OS/kernel, interfaces, rotas, IPv4 forwarding e candidate networks. **Status: LAB VALIDATED para Linux controlado.**

### v0.4b.3 — Context-aware Credentialed Discovery
- combinar protocolo + scope + serviço detectado + fingerprint/device class;
- selectors opcionais de OS family, device type, hostname/vendor e realm;
- perfis Windows domain e Windows local separados;
- `failure_budget_per_job` declarado por profile para futura proteção de credenciais compartilhadas;
- nunca tentar credencial somente porque um IP foi descoberto;
- planner seguro que consome o JSON do Network Discovery e produz um plano sem resolver secrets;
- orquestração por ativo com stop-after-success nas próximas integrações;
- primeira validação corporativa no Discovery Node P01-MGMT01.
- **Status:** v0.4b.3.1 LAB VALIDATED. O Windows 11 validou três gates: (1) sem WinRM -> `not_planned`; (2) WinRM disponível + sem profile -> `not_planned`; (3) WinRM + profile workstation/domain compatível -> `adapter_candidate`, ainda sem resolver secret. Circuit breaker permanece pendente do executor multi-target.

### v0.4b.4 — WinRM Credentialed Enrichment
- WinRM HTTP/HTTPS;
- password + NTLM na primeira iteração;
- Context-aware Credential Profiles;
- PowerShell/CIM read-only;
- identity/domain/OS/network/firewall/hotfixes;
- candidate networks sem auto-scan;
- JSON + SHA256 sem secrets.
- **Status:** AUTH/NTLM validado no P01-MGMT01. A coleta full v0.4b.4 encontrou o limite `The command line is too long.`.

### v0.4b.4.1 / v0.4b.4.2 — Modular WinRM Collection
- divide a coleta em seções PowerShell pequenas e independentes;
- preserva seções bem-sucedidas em falhas parciais;
- compatibilidade Windows PowerShell 5.1;
- filtra /32 locais de candidate networks;
- registra `collection_sections` e `failed_section_count`;
- mantém candidate networks sem auto-scan.
- **Status:** LAB VALIDATED no P01-MGMT01 e no P01-DC01, incluindo profile local e profile de domínio.

### v0.4b.4.3 — WinRM Failure Semantics
- separar falha de transporte de credencial inválida;
- não consumir failure budget de credencial em ConnectTimeout/ConnectionError;
- preparar o executor multi-target e circuit breaker.
- **Status:** runtime validated. O comportamento foi exercitado em Domain Controller e workstation de domínio; falhas de transporte não são interpretadas como credencial inválida.

### v0.4b.5 — Multi-target Credentialed Executor
- consumir somente targets/protocolos marcados `adapter_candidate`;
- revalidar profile/context antes de resolver secret;
- dispatch controlado para SSH e WinRM;
- concorrência conservadora e determinística;
- shared-credential circuit breaker por job;
- apenas `failure_category=authentication` consome failure budget;
- `transport` não penaliza credential health;
- evidência agregada por job + referências por target;
- dry-run obrigatório no primeiro LAB.
- **Status:** LAB VALIDATED em dry-run, AUTH-only e FULL nos cinco ativos do P01LAB.

### v0.4b.6 — Assessment Context & Credential Intake
- Assessment Manifest persistente e não secreto;
- domínios/realms declarados como hints, nunca como prova;
- estados de evidência `declared`, `observed` e futuro `credentialed_confirmed`;
- taxonomy independente para `realm_kind`, `target_classes`, `privilege_class`, `purposes` e protocolo;
- intake wizard grava profile metadata + Secret Provider reference, nunca a senha;
- perfis high-privilege exigem acknowledgement, failure budget 1 e uma tentativa;
- planner v0.4b.3.2 consome manifest e só promove realm AD para `observed` quando houver evidência compatível;
- conflito entre realm declarado e observado bloqueia planning em vez de escolher silenciosamente;
- rich profiles não podem ser usados sem contexto.
- **Status:** LAB VALIDATED no P01LAB. Positive gate confirmou declared+observed -> adapter_candidate; negative gate confirmou declared-only -> not_planned, sem resolver secret ou autenticar.

### v0.4b.7+ — próximos adapters
- SNMPv3/SNMPv2c;
- Kerberos/HTTPS/certificate para WinRM;
- WMI/DCOM fallback quando necessário;
- auditoria de autenticação multi-protocolo.

## v0.4c — Asset Resolver

### v0.4c.0 — Offline correlation foundation
- consumir Network Discovery + target results FULL de WinRM/SSH + Assessment Manifest opcional;
- nunca auto-merge por IP isolado;
- strong identifier exato ou namespace + network corroboration para auto-merge;
- Network Discovery observations permanecem seeds independentes;
- provenance por campo;
- conflitos explícitos sem silent overwrite;
- realm `observed` separado de `credentialed_confirmed`;
- output determinístico JSON + SHA256;
- zero network access, authentication ou secret resolution.
- **Status:** LAB VALIDATED. O P01LAB real resolveu 5 Network Discovery assets + 5 FULL observations em 5 logical assets, 0 unresolved, 0 ambiguous e 0 conflicts. O realm de autenticação foi separado da identidade de diretório.

### Próximas iterações v0.4c
- AD computer object / objectGUID / SID;
- system UUID / SMBIOS UUID / service tag;
- Windows Collector e Linux Collector locais;
- registry persistente de asset IDs entre assessment runs;
- SNMP sysName/sysObjectID e VMware identifiers futuramente.

Objetivo: um ativo lógico, múltiplas fontes de evidência, sem duplicidade no relatório.

## v0.4d — Dynamic Scope Expansion

Usar evidências de interfaces, rotas, VLANs e neighbors obtidas pela v0.4b para descobrir novas redes candidatas e expandir o discovery somente dentro de limites explicitamente autorizados.

Guardrails:
- auto-expansão desligada por padrão;
- authorized_supernets + exclude_scopes;
- max_depth / max_new_networks / max_hosts;
- deduplicação de redes já visitadas;
- sem pivot/jump automático;
- sem herança automática de credenciais;
- redes sem alcance ficam registradas para futuro Remote Discovery Node/Sensor.

## Discovery Nodes / Sensors

O P01 deve suportar múltiplos Discovery Nodes em segmentos distintos. Um node escaneia apenas redes alcançáveis a partir dele e envia evidências para consolidação posterior. Não usar ativos arbitrários como pivots.

O LAB inicial usará P01-MGMT01 como Discovery Node por possuir acesso ao segmento NAT e ao segmento interno do laboratório.

## Depois da v0.4

- Reporting Engine v0.1;
- SNMP/LLDP/CDP e topologia ampliada;
- plugins de fabricantes/controladoras;
- remote discovery nodes/sensors;
- CVE correlation e Patch Compliance.


## v0.5 — Discovery Node / Evidence Bundle / Central Ingestion

### v0.5a — Evidence Bundle Format
- formato portátil único para connected upload e offline/manual import;
- bundle manifest + evidence inventory + SHA256;
- preservar assessment/run/node identity e component/schema versions;
- no secret values or Secret Provider references;
- formato transportável como `.p01bundle`.
- **Status:** LAB VALIDATED no P01LAB. P01LAB-BUNDLE-R1 empacotou 8 artifacts, validou 9 inventory entries, outer SHA256, zero secret material e transport mode agnostic.

### v0.5b — Offline Export / Import
- validar o bundle antes de materializar qualquer payload;
- preservar o `.p01bundle` original como raw evidence;
- safe materialization sem `extractall`;
- import idempotente por bundle ID + SHA256;
- receipt JSON + SHA256;
- reexecutar Asset Resolver usando somente evidências importadas;
- comparar semanticamente resultado server-side com o Asset Resolver edge embarcado;
- segunda importação do mesmo bundle retorna `already_imported`.
- **Status:** LAB VALIDATED. P01LAB-BUNDLE-R1 foi importado em store limpo; server-side Asset Resolver reproduziu 5 logical assets, 0 unresolved, 0 ambiguous, 0 conflicts, semantic_match=true; segunda importação retornou already_imported; receipt JSON/SHA256 validado.

### v0.5c — Central Ingestion API
- localhost-only HTTP ingestion foundation;
- mesmo `import_bundle()` da v0.5b;
- mandatory Content-Length + X-P01-Bundle-SHA256;
- idempotency key;
- upload-size guard;
- staging before validation/import;
- GET status + health endpoint;
- non-loopback bind rejected.
- **Status:** LAB VALIDATED. Positive path, idempotência, status lookup, semantic equivalence, bind loopback-only, negative gates 400/422/422/413 e connection hygiene v0.5c.1 foram validados no P01LAB.

### v0.5d — Connected Discovery Node Upload
- upload outbound-only do Discovery Node para o servidor;
- HTTPS com TLS 1.2+;
- mTLS na primeira iteração;
- server certificate validation no Node;
- client certificate validation no servidor;
- `X-P01-Node-ID` ligado à identidade DNS SAN/CN do certificado cliente;
- bundle `node_id` deve coincidir com o node autenticado;
- status lookup escopado ao node autenticado;
- retries limitados apenas a falhas de transporte;
- nenhum retry automático de 4xx/TLS-auth failures;
- no server-initiated arbitrary execution.
- **Status:** CANDIDATE implementado; primeiro gate será mTLS local usando o bundle P01LAB já homologado, seguido por client/server em hosts distintos.

### v0.5e — Optional Installed Service
- portable remains default for one-shot assessments;
- optional Windows/Linux service for recurring assessments.
