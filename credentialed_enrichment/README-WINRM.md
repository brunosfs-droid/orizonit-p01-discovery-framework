# P01 Windows WinRM Credentialed Enrichment — v0.4b.4

Adapter autenticado **read-only** para Windows.

## Escopo inicial

- WinRM HTTP/5985 ou HTTPS/5986;
- password auth;
- transport NTLM;
- Context-aware Credential Profiles;
- bounded attempts / stop after success;
- PowerShell/CIM read-only;
- identidade, domínio, OS, hardware, rede, DNS, firewall e hotfixes recentes;
- secure-channel check somente quando aplicável;
- candidate networks sem scan automático;
- JSON + SHA256 sem secrets.

Kerberos, certificates, CredSSP e WMI/DCOM fallback ficam para incrementos posteriores.

## Dependência

\`\`\`powershell
python -m pip install -r .\credentialed_enrichment\requirements-winrm.txt
\`\`\`

## Segurança

- senha nunca na linha de comando;
- secret vem do Secret Provider;
- profile + target + contexto precisam dar match;
- \`same_profile_retries = 0\`;
- o payload PowerShell remoto é fixo e read-only;
- não executa \`Enable-PSRemoting\`;
- não altera firewall, TrustedHosts ou secure channel;
- candidate networks usam \`auto_scan=false\`.

## Primeiro LAB

Validar primeiro em um único target Windows, usando \`--auth-only\`. Só depois executar full enrichment.
