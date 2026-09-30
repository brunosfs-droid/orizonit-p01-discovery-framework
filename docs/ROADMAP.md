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
- **Status:** v0.4b.3 LAB VALIDATED para planning/matching. v0.4b.3.1 adiciona status/skip reasons explícitos. O Windows 11 validou dois estágios do gate: (1) WinRM ausente -> no protocol; (2) após preparação manual do LAB, Network Discovery detectou 5985/winrm-http. Próximo teste: WinRM detectado porém sem profile elegível deve continuar `not_planned`. Circuit breaker permanece pendente do executor multi-target.

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
- **Status:** candidate; derivado de evidência real em que AUTH-only teve ConnectTimeout e a execução full subsequente autenticou com o mesmo profile.

### v0.4b.5+ — próximos adapters/executor
- SNMPv3/SNMPv2c;
- Kerberos/HTTPS/certificate para WinRM;
- WMI/DCOM fallback quando necessário;
- executor multi-target + shared-credential circuit breaker;
- auditoria de autenticação multi-protocolo.

## v0.4c — Asset Resolver

Correlacionar:

- IP/MAC;
- hostname/FQDN;
- AD computer object;
- Windows Collector;
- Linux Collector;
- Network Discovery;
- serial/UUID quando disponível;
- SNMP sysName/sysObjectID futuramente.

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
