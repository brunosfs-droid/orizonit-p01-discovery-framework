# P01 Network Discovery Scanner v0.4.0 — MVP

Componente de descoberta ativa **sem credenciais** do Produto 01 — Infrastructure Assessment da Orizon IT.

## Objetivo

Descobrir ativos em uma ou mais faixas IPv4 autorizadas antes da coleta aprofundada por Windows/Linux/SNMP/SSH/WinRM. O scanner produz inventário preliminar, portas TCP, fingerprints básicos, reverse DNS, correlação ARP local, SSDP e classificação com nível de confiança.

## Guardrails

- exige `--ack-authorized-scan`;
- não executa exploits;
- não tenta credenciais na v0.4a;
- limite padrão de 2.048 IPs por execução, salvo `--allow-large-scope`;
- suporta múltiplos `--target` e `--exclude`;
- recomenda segmentar scopes grandes;
- saída JSON + SHA256;
- resultados são classificados como dados confidenciais do cliente.

## Alvos suportados

```text
192.168.1.0/24
192.168.1.10
192.168.1.10-192.168.1.50
192.168.1.10-50
```

## Exemplo — rede doméstica

```powershell
python .\P01_Network_Discovery_Scanner.py `
  --target 192.168.1.0/24 `
  --exclude 192.168.1.255 `
  --profile safe `
  --workers 64 `
  --run-label CASA-LAB `
  --output-dir .\output `
  --ack-authorized-scan
```

Em Linux:

```bash
python3 ./P01_Network_Discovery_Scanner.py \
  --target 192.168.1.0/24 \
  --profile safe \
  --run-label CASA-LAB \
  --output-dir ./output \
  --ack-authorized-scan
```

## O que é coletado

- IP;
- resposta ICMP quando disponível;
- entrada ARP/neighbor local quando disponível;
- reverse DNS;
- portas TCP definidas pelo profile;
- banner de alguns serviços plaintext;
- HTTP headers básicos;
- TLS negociado e hash SHA256 do certificado em HTTPS;
- SSDP/UPnP em rede local;
- device type e OS *guess* com `High`, `Medium` ou `Low` confidence.

## Limitações conhecidas

A ausência de resposta não prova ausência do dispositivo. Celulares em sleep, hosts com ICMP bloqueado, equipamentos sem portas acessíveis e segmentos roteados podem aparecer parcialmente ou não aparecer. ARP só é útil no mesmo domínio L2. O fingerprint desta versão é heurístico e deve ser enriquecido em v0.4b por credenciais autorizadas.

## Próxima etapa — v0.4b

- Credential Manager com referências a secrets, sem senhas em arquivos;
- SNMPv3/SNMPv2c por profile autorizado;
- SSH;
- WinRM/WMI;
- tentativa ordenada e limitada por tipo/faixa;
- proteção contra lockout;
- Asset Resolver para deduplicar AD, Network Scanner e Deep Collectors.
