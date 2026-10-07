# ADR 0041 — recuperação de workspace e fence por banco

Data: 07/10/2026. CANDIDATE opt-in em schema8; qualificado em CI; [registro](validation/WORKSPACE_RECOVERY_CI_v0.6.27.md).

## Decisão

A migração0008 substitui somente workspace_active_fence, preservando SQL1–7 e
seus checksums. O lock precisa estar no database OID da conexão, além de PID/key
da sessão. pg_locks inclui locks de outros bancos no cluster: um runtime copiado
de outro banco não pode usar aquela sessão como prova de contexto ativo.
O upgrade exige ausência de coordenador vivo, como0007.

Recovery migrations têm prefixo explícito8. Prefixos4/5/6/7 permanecem fixos;
readers workspace aceitam8 opt-in, enquanto o listener deste incremento passa
a exigir8 no startup. Não ocorre upgrade automático do LAB nem fallback legado.

Após verificar o par banco/store e privilégios, manutenção reinicia runtime em
closed, invalida generation/lease/PID e limpa last_txid das revisões. XID é marcador
da linha temporal do cluster, não identidade durável do conteúdo; sua coincidência
em outro cluster não pode impedir incremento da revisão. Conteúdo, revisões,
observações, declarações, relações, planos e recibos não são reescritos.

Prepare exige generation esperada e lock transacional sem coordenador vivo.
A identidade de manutenção precisa de privilégio apropriado; não é operação de
operador nem rota HTTP. Novo coordenador/abertura são explícitos; nenhum job/scan
é retomado automaticamente.

## Qualificação e fronteira

Harness destrutivo somente em GitHub Actions, DB/user/host/container fixos,
cluster conferido antes de reset/DDL e destino novo template0. Dump custom,
restore em transação e stores copiados/hash/revalidados. Runtime e last_txid são
metadados voláteis; restante das28 tabelas é comparado logicamente, junto de RLS
e ACLs de roles já existentes no mesmo cluster.

Restore conserva ACLs, incluindo REVOKE PUBLIC dos helpers privados. --no-owner
é seguro nesse fixture com maintenance owner confiável; --no-privileges não é
usado. Criação/restore de roles globais em outro cluster ainda não é qualificada.

Snapshot/grafo e recibos devem permanecer, tokens antigos/acesso à outra base
devem falhar, corrupção do receipt deve ser recusada e a primeira escrita deve
incrementar revision. Teste adversarial usa lock real em outro banco para provar
a rejeição de runtime clonado.

Sem backup operacional/agendamento/PITR/RPO/RTO ou restore concorrente.
Migração/backfill completo, audit HTTP, UI/Mapper, reports legados e LAB continuam
gates. [Contrato](WORKSPACE_RECOVERY_v0.6.27.md).
