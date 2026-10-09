# Cancã v0.6.45 — histórico transacional de intenções e decisões

Migração 0010 opt-in, manutenção com coordenador parado. O comando
`python persistence/P01_Workspace_Intent_Ledger.py migrate` exige role administrativa
no banco explicitamente configurado pelo operador. Não executar no LAB antes
de capturar/verificar backup e aprovar seu upgrade operacional.

Os contratos antigos de migração continuam pinados: `legacy=True` termina em 9;
`intents=True` admite até 10 e verifica todos os checksums. Os readers atuais
workspace aceitam esse prefixo aditivo, preservando mínimos e grants anteriores.

## Registro e transições

Serviço interno `persist_scan_intent` calcula a prévia com política confiável e
persiste somente identificadores, modo e hashes; CIDRs, comandos e credenciais
não são armazenados. Role SQL autenticada é a autoria; nesta versão ainda não
há vínculo separado com identidade humana/SSO nem separação maker/checker.
`request_id` é idempotente por workspace e role, sem renovar TTL no replay.
Relógio do PostgreSQL fixa criação/expiração, TTL entre 1 e 300 segundos.

`decide_scan_intent` permite pending → approved/rejected/revoked;
approved → consumed/revoked; os demais estados são terminais. A palavra
approved representa exclusivamente uma decisão de revisão registrada,
**não uma autorização executável**. Mesmo consumed retorna
`execution_authorized=false`; nenhum executor consulta essas tabelas.

Tabelas têm FORCE RLS, autoria vinculada à role, FKs compostas e histórico
sem políticas de UPDATE/DELETE. Trigger SQL serializa transições e impede
consumo sem aprovação, sequência inválida, lease/geração trocados e expiração,
inclusive em INSERT direto. Contas de manutenção são confiáveis e podem
alterar dados; não se afirma imutabilidade criptográfica ou contra DBA.

Transações usam o fence e lock de revisão do workspace. Registro e carimbo
de revisão confirmam ou revertem juntos. Replay não concede nova ação. O
serviço revalida grants/lease antes e depois; erro após commit pode ser
reconciliado pelo request_id e histórico, jamais por disparo automático.

## Reinício e recuperação

Histórico permanece legível em geração nova; uma intenção de geração/lease
antigos não pode ser aprovada/consumida, mesmo ainda dentro do TTL. Alteração
da política ou digest também invalida a operação. O reset de recuperação
mantém as decisões como história e remove o contexto vivo anterior.

Validação: `python -m unittest discover -s tests -p 'test_workspace_intent_ledger.py' -v`.
Casos SQL dependem de `CANCA_TEST_WORKSPACE_POSTGRES=1` e banco descartável;
CI PostgreSQL 16/17, nunca base operacional. Incluem transições/replay,
expiração, RLS A/B, read-only, autoria, revogação de grant, rollback e restart.

## Limites e próximos gates

API HTTP de decisões, identidade humana separada, política de aprovação real,
secret provider isolado e execução AUTH/FULL continuam desabilitados.
R02/R06 parciais. Testes EVE-NG e recovery cross-cluster não são substituídos
por CI sintético. Próxima qualificação: dump/restore schema10 e concorrência
entre decisões antes da integração HTTP.
