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
- credentials compartilhadas com circuit breaker/failure budget;
- nunca tentar credencial somente porque um IP foi descoberto;
- orquestração por ativo com stop-after-success;
- primeira validação corporativa no Discovery Node P01-MGMT01.

### v0.4b.4+ — próximos adapters
- SNMPv3/SNMPv2c;
- WinRM/WMI;
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
