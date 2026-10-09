# Cancã v0.6.47 — concorrência e idempotência do ledger

Esta entrega qualifica o ledger não executável da v0.6.45 e a recuperação
schema10 da v0.6.46. Não adiciona autorização para executar scanner.

## Invariantes sob concorrência real

Os testes PostgreSQL usam duas conexões independentes e barreira de partida,
além do coordenador de sessão e do bloqueio transacional de revisão existente.

1. Duas decisões conflitantes para intenção pending (approved/rejected):
   exatamente uma decisão persistida, perdedora recusada com
   `intent_transition_denied` e uma única revisão adicional.
2. Duas requisições simultâneas com o mesmo request_id e decisão:
   um registro e um replay idempotente, sem renovar TTL e sem revisão extra.
3. Corrida entre revoked e consumed após approved:
   exatamente uma transição terminal, sequência 1/2 íntegra e perdedora
   recusada sem qualquer retomada de execução.
4. A leitura posterior mantém `execution_authorized=false`.

Esses casos complementam os testes anteriores de consumo concorrente, rollback,
FORCE RLS, grants separados A/B, expiração, mudança de lease/geração e restauração
sem reautorizar. O SQL permanece append-only e somente histórico.

## Execução segura

```bash
python -m unittest discover -s tests -p 'test_workspace_intent_ledger.py' -v
```

Sem `CANCA_TEST_WORKSPACE_POSTGRES=1`, os testes SQL devem ser pulados.
Com essa variável, executar **apenas** no PostgreSQL sintético descartável de
GitHub Actions (PG16 e PG17). Não apontar para EVE-NG, lab persistente ou produção.
O pipeline Workspace Foundation já executa a suíte; a v0.6.47 inclui também a
compilação explícita do módulo ledger e dos testes.

## Limites e gates

Esta qualificação não implementa segregação de funções maker/checker, identidade
humana, HTTP para decisões, execução AUTH/FULL, nem valida a recuperação
cross-cluster, secrets/TLS, RPO/RTO e E0/EVE-NG. R02/R06 e Product Alpha
permanecem abertos. Não declarar aprovação operacional com base exclusiva em CI.
