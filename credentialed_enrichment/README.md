# P01 SSH Credentialed Enrichment — v0.4b.2

Primeiro adaptador autenticado do Produto 01.

## Objetivo

Autenticar via SSH em um target **explicitamente autorizado**, usando Credential Profiles e Secret Provider já validados, e executar somente uma allowlist de comandos read-only para enriquecer:

- identidade/hostname;
- kernel/plataforma;
- interfaces IPv4;
- rotas;
- estado de IPv4 forwarding;
- candidate networks para uso futuro pelo Dynamic Scope Expansion v0.4d.

## Segurança

- nenhum segredo vai para stdout, JSON ou logs;
- password vem do Secret Provider apenas no momento da conexão;
- `allow_agent=False` e `look_for_keys=False` evitam credenciais locais acidentais;
- no máximo um attempt por profile;
- candidate profiles são limitados;
- para após primeiro sucesso;
- comandos remotos são fixos e read-only;
- não executa `sudo`;
- não altera configuração;
- não faz pivot;
- não escaneia redes descobertas;
- host key policy deve ser `tofu` ou `strict`.

## Dependência

O adaptador usa Paramiko, instalado separadamente:

```powershell
python -m pip install -r .\credentialed_enrichment\requirements-ssh.txt
```

A dependência não é vendorizada no repositório.

## Primeiro LAB

```powershell
python .\credentialed_enrichment\P01_SSH_Enricher.py `
  --profiles .\credential_manager\credentials.local.json `
  --target 192.168.15.1 `
  --port 22 `
  --host-key-policy tofu `
  --max-candidates 1 `
  --run-label CASA-LAB-SSH-R1 `
  --output-dir .\output `
  --ack-authorized-access
```

Na primeira conexão `tofu`, a host key será registrada em:

```text
%USERPROFILE%\.orizonit\p01\known_hosts
```

Execuções seguintes detectam mudança de host key.

## Teste apenas de autenticação

```powershell
python .\credentialed_enrichment\P01_SSH_Enricher.py `
  --profiles .\credential_manager\credentials.local.json `
  --target 192.168.15.1 `
  --auth-only `
  --max-candidates 1 `
  --run-label CASA-LAB-SSH-AUTH `
  --output-dir .\output `
  --ack-authorized-access
```

## Saída

```text
P01-SSH-Enrichment_<timestamp>_<run-label>.json
P01-SSH-Enrichment_<timestamp>_<run-label>.json.sha256
```

## Interpretação de candidate networks

Redes observadas em interfaces/rotas são apenas evidência:

```json
{
  "network": "192.168.50.0/24",
  "authorization_status": "unassessed",
  "auto_scan": false
}
```

A v0.4b.2 **nunca inicia scan recursivo**. A decisão de expansão ficará no v0.4d após Asset Resolver v0.4c.
