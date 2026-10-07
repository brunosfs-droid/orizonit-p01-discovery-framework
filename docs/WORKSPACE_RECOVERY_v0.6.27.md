# Cancã — Workspace Recovery v0.6.27

CANDIDATE opt-in em banco isolado, schema8. [ADR0041](ADR_0041_Workspace_Recovery_v0.6.27.md).
Esta versão do listener workspace exige8; a v0.6.26 qualificada continua pinada em7.

## Contratos

| Operação de manutenção | Conduta |
| --- | --- |
| migrate | Migra explicitamente até8; recusa coordenador ativo; preserva checksums1–7. |
| inspect | Exige maintenance role; retorna generation/state/contagem, sem inventário. |
| prepare-restored | Generation esperada e ausência de coordenador; limpa marcadores de cluster, closed e generation+1. |

CLI P01_Workspace_Recovery.py usa configuração libpq externa, sem DSN/senha em
args. Os comandos abaixo são contratos de desenvolvimento, sem pedido de execução
no LAB:

~~~sh
python persistence/P01_Workspace_Recovery.py migrate
python persistence/P01_Workspace_Recovery.py inspect
python persistence/P01_Workspace_Recovery.py prepare-restored --expected-generation 10
~~~

Prepare não cria dump, copia store, restaura grants ou corrige evidência. Usar
somente após verificação administrativa do par restaurado e ownership/ACLs.
workspace_restore_busy impede ação durante coordenador vivo, mesmo closed;
workspace_restore_stale impede confirmação antiga. Erros não exibem conexão/secret.

A primeira escrita após prepare deve incrementar revisão; marker last_txid não
é preservado como identidade de conteúdo. Tokens/generation antigos são negados.
DB/store/configuração/roles são um conjunto de recuperação; restaurar dados sem
ACLs privadas não constitui ambiente qualificado.

## Gates do incremento

CI PG16/17: migração8/upgrade guard, prefixos e checksums, reset sem reescrever
conteúdo, primeira revisão, generation stale, maintenance role, token antigo,
RLS/ACL privado e runtime clonado com lease de outro banco. Harness em destino
descartável: dump/restores/stores/hash,28 tabelas de conteúdo/registry/revisão,
snapshot/grafo, replay de recibos, corrupção recusada e ACL/RLS.

O harness tests/workspace_backup_restore_smoke.py é destrutivo e recusa ambiente
fora do CI. Não executá-lo no LAB. Sua qualificação usa mesmo cluster/major e roles
sintéticas já existentes, sem escritores concorrentes; não comprova restore de
roles/segredos/certificados em outro cluster ou backup operacional.

O terminal local ficou indisponível antes deste incremento. Qualificação local
não é alegada; código e testes são validados em workflows remotos, com fonte/jobs
pinados quando aprovados. Próximo: backfill/import revisado e leitores por revisão,
audit HTTP workspace e UI/Mapper após os gates correspondentes.
