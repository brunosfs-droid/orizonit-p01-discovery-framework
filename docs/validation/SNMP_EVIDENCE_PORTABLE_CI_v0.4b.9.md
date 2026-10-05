# Qualificação sintética SNMP evidence/portable — v0.4b.9

Data: 05/10/2026 (-03). Estado: CI pendente; operação real CANDIDATE.

Base: `e9250e12d53bb2e941c9e6bb888561166f69b94e`.
O adapter SNMP v0.4b.7 permanece intacto. Nenhum LAB/target real foi alterado.

Qualificação local do incremento: 88 testes SNMP sem skips, incluindo os
26 casos do adapter, 28 de planejamento/executor e 34 de evidência/portable.
Regressão geral: 643 testes, PASS com 140 skips esperados por dependências
opcionais/OS/PostgreSQL; 93.128s. Compilados 113 arquivos Python e validados
25 JSONs. Prova de matriz CI será registrada após conclusão.

A primeira regressão mostrou `export_busy` no teste preexistente de slot
compartilhado de export Web. A suite isolada desse componente passou (9 casos,
9.154s), e a repetição geral passou sem alterar código Web ou esse teste.

O workflow `snmp-ci.yml` requer PySNMP e jsonschema e executa a cadeia com UDP
loopback em Linux/Windows e Python 3.10/3.12/3.13. Os seis casos de integração
com agente real não podem ser omitidos nessa matriz. A suite default pode
omitir testes que requerem runtime opcional/OS/PostgreSQL não disponível.

O incremento verifica contratos e OIDs, identidade/proveniência, AUTH separado
de inventário, FULL parcial, arquivos privados/exclusivos, retomada sem rede,
drift, retry explícito, bundle de bytes brutos e replay sem imports de providers.
Essa prova não qualifica vendors reais, ACL NTFS ou autoria criptográfica.

[Contrato](../SNMP_EVIDENCE_PORTABLE_v0.4b.9.md) ·
[ADR](../ADR_0035_SNMP_Evidence_and_Portable_v0.4b.9.md).
