# Cancã v0.6.46 — recuperação do ledger schema10

Estende o harness de CI isolado com `--intent-ledger`, mantendo os modos
schema8 e schema9. Esse harness continua destrutivo **somente no serviço
PostgreSQL descartável de GitHub Actions**, com todas as verificações de
container/cluster/host/usuário/banco existentes. Não executar no EVE-NG.

A fixture inclui intenção pendente e decisão aprovada, objetos, relações,
evidências originais e recibos idempotentes. O dump custom e restore atômico
preservam conteúdo, revisão, FORCE RLS e ACLs das roles sintéticas existentes.
Após reset do runtime, ambos os registros permanecem legíveis como história;
context_current=false e execution_authorized=false. Uma tentativa de consumir
a aprovação com geração/lease novos falha com intent_stale. Nenhum job retoma.

As snapshots antes/depois incluem workspace_scan_intents e
workspace_scan_decisions e as tabelas de legado; alterações por uma tentativa
recusada não podem aparecer. A próxima escrita comum incrementa exatamente
uma revisão, comprovando o reset dos marcadores transacionais.

## Evidência e limites

Workspace Foundation CI executa três modos de recuperação em PG16/17.
A execução do novo passo deve concluir WORKSPACE BACKUP RESTORE PASS,
schema_migration=10 e intent_ledger_preserved_without_reauthorization=true.
O teste do guard verifica também que --intent-ledger não inicia Docker,
conexão ou fixture fora do CI permitido.

Este é restore em banco novo **no mesmo cluster**, com roles existentes.
Não fecha recuperação cross-cluster, restauração de secrets/TLS, RPO/RTO
operacional ou E0/EVE-NG. A versão v0.6.45 foi integrada no PR #156 após os
oito workflows passarem em 668622c2f8c4309d1c3cab063a54b280ef1bffdb.
A falha inicial de NULL no guard SQL foi corrigida antes do merge.
