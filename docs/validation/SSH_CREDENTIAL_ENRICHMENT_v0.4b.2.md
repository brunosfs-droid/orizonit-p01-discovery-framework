# P01 SSH Credentialed Enrichment v0.4b.2
## Plano de validação

### Pré-requisitos
- Credential Manager v0.4b.1 já validado.
- Profile `home-router-ssh` com scope `/32`.
- Secret armazenado em Windows Credential Manager.
- TCP/22 acessível no target.
- Snapshot/backup não é necessário porque o adaptador executa apenas comandos read-only, mas o acesso deve ser autorizado.

### Gate 1 — testes locais
- Python compile.
- JSON Schema parse.
- Unit tests.
- Command catalog validation.

### Gate 2 — auth-only
Executar com `--auth-only`.
Esperado:
- 1 profile candidato;
- 1 tentativa;
- autenticação success/failure claramente registrada;
- nenhum segredo na saída;
- host key fingerprint registrada;
- JSON + SHA256.

### Gate 3 — read-only enrichment
Sem `--auth-only`.
Esperado, dependendo do shell do equipamento:
- hostname;
- banner/version SSH;
- pelo menos um método de interfaces (`ip` ou `ifconfig`);
- rotas (`ip route` ou `route -n`);
- candidate networks;
- falha de comandos não interrompe toda a coleta.

### Gate 4 — segurança
- segredo não aparece em JSON;
- `same_profile_retries = 0`;
- `attempts_made <= max_candidates`;
- `candidate_networks[*].auto_scan = false`;
- nenhuma alteração de configuração;
- TOFU salva host key; segunda execução aceita a mesma key;
- host key alterada deve falhar.

### Observação
Roteadores de operadora podem expor SSH restrito ou credenciais diferentes da GUI Web. Falha de autenticação nesse equipamento não invalida o Credential Manager nem o adaptador; nesse caso, validar o adapter contra um Linux/roteador LAB controlado.
