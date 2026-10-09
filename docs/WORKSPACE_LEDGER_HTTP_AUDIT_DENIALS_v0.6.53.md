# Cancã v0.6.53 — auditoria de requisições negadas

O teste HTTP verifica que requisições de histórico de ledger rejeitadas por parâmetros inesperados (incluindo valores que parecem credenciais) e por sessão encerrada continuam auditadas com classificação fixa `scan_intent_history`, sem vazar token, identificador de intenção, query ou rota literal. Os testes verificam que não ocorre dispatch ao serviço após as rejeições.

Gate: `tests/test_workspace_live_intent_http.py` sob Python CI e Workspace Foundation CI, seguido de todos os oito workflows antes do merge. v0.6.52 integrada pelo PR #163. Sem mudanças de schema, habilitação de scanner, execução no EVE-NG ou homologação de recuperação cross-cluster. R02/R06 e E0 permanecem pendentes.
