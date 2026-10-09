# Cancã v0.6.50 — entradas adversariais no histórico HTTP do ledger

Amplia o gate de leitura auditada do ledger schema10, sem alterar contratos SQL,
migrar dados ou habilitar scanner.

## Cobertura

- Rejeitar parâmetros de query duplicados, ausentes, desconhecidos, inválidos
  ou com supostas credenciais; não repassar a requisição ao serviço.
- Rejeitar sessão encerrada antes de consultar o histórico.
- Rejeitar IDs malformados sem executar handler de histórico.
- Preservar o bloqueio por auditoria privada da v0.6.48 e a compatibilidade
  das rotas legadas protegidas pela v0.6.49.

Os testes são HTTP sintéticos e se executam em
`tests/test_workspace_live_intent_http.py`, cobertos pelo Python CI e pelo
Workspace Foundation CI. Não constituem homologação SQL end-to-end para
revogação em dois workspaces; esses gates, bem como E0/EVE-NG, recovery
cross-cluster, maker/checker e R02/R06, permanecem pendentes.

Não executar laboratório, varredura ativa nem operações de escrita em alvos.
