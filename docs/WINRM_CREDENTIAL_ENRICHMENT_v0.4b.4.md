# P01 WinRM Credentialed Enrichment v0.4b.4 — LAB

## Ordem de validação

1. instalar \`requirements-winrm.txt\`;
2. criar profile WinRM autorizado no arquivo local;
3. armazenar secret no Windows Credential Manager;
4. validar \`auth-only\` em P01-MGMT01;
5. executar full enrichment;
6. repetir em P01-DC01;
7. ligar Windows 11, rerodar Network Discovery e validar o profile apropriado;
8. manter profiles de domínio separados de profiles locais /32.

## Critérios

- context/profile match correto;
- 1 bounded attempt;
- zero same-profile retries;
- nenhum secret no JSON;
- \`collection_status=collected\`;
- identity/domain/OS;
- interfaces/routes/DNS;
- firewall profiles;
- secure channel somente quando aplicável;
- recent hotfixes;
- candidate networks com \`auto_scan=false\`;
- JSON + SHA256.

## Não objetivos

O adapter não habilita WinRM, não cria listeners, não modifica TrustedHosts, não altera firewall e não executa reparo de domínio.
