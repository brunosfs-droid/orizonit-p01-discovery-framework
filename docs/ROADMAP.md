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

- Credential Profile sem segredo em arquivo;
- Secret Provider abstraction;
- SNMPv3/SNMPv2c;
- SSH;
- WinRM/WMI;
- prioridade e escopo por credencial;
- tentativas limitadas e lockout protection;
- auditoria de autenticação;
- nenhum segredo em JSON/log.

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

## Depois da v0.4

- Reporting Engine v0.1;
- SNMP/LLDP/CDP e topologia;
- plugins de fabricantes/controladoras;
- remote discovery nodes/sensors;
- CVE correlation e Patch Compliance.
