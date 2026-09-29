# P01 Network Discovery Scanner v0.4.1 — Candidate

Componente de descoberta ativa **sem credenciais** do Produto 01 — Infrastructure Assessment da Orizon IT.

## Objetivo

Descobrir ativos em uma ou mais faixas IPv4 autorizadas antes da coleta aprofundada por Windows/Linux/SNMP/SSH/WinRM. O scanner produz inventário preliminar, portas TCP, fingerprints básicos, reverse DNS, correlação ARP local, SSDP e classificação com nível de confiança.

## Melhorias da v0.4.1

- warning de *scope sanity* quando o escopo não contém IP local nem gateway;
- `hostname_source` e `hostname_confidence`;
- identidade local do execution host tem precedência sobre reverse DNS;
- `mac_address_type` distingue MAC universal/localmente administrado;
- correlação de mesmo MAC em múltiplos IPs sem auto-deduplicação;
- SSDP tenta a interface IPv4 local pertencente ao escopo em hosts multi-homed;
- novos contadores de correlação no summary.

## Guardrails

- exige `--ack-authorized-scan`;
- não executa exploits;
- não tenta credenciais na v0.4a/v0.4.1;
- limite padrão de 2.048 IPs, salvo `--allow-large-scope`;
- suporta múltiplos `--target` e `--exclude`;
- saída JSON + SHA256;
- resultados devem ser tratados como dados confidenciais do cliente.

## Exemplo

```powershell
python .\P01_Network_Discovery_Scanner.py `
  --target 192.168.15.0/24 `
  --profile safe `
  --workers 64 `
  --run-label CASA-LAB-R2 `
  --output-dir .\output `
  --ack-authorized-scan
```

## Interpretação de identidade

O scanner trabalha inicialmente com **IP endpoints**. Um mesmo equipamento pode aparecer em mais de um IP. A v0.4.1 apenas cria `identity_correlations`; o merge definitivo será responsabilidade do futuro **Asset Resolver v0.4c**.

Reverse DNS também não é identidade canônica. O campo `hostname_source` deve ser considerado junto com `hostname_confidence`.

## Próximas etapas

- concluir validação v0.4.1;
- enriquecimento não autenticado adicional (OUI/vendor, mDNS e fingerprints mais ricos, conforme avaliação);
- v0.4b: Credential Manager + SNMP/SSH/WinRM;
- v0.4c: Asset Resolver.
