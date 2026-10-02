# PostgreSQL P01LAB — recuperação R1 aceita

02/10/2026 (-03). **LAB VALIDATED no par sintético R1**, por sete capturas fornecidas pelo operador. Host Rocky P01-LNX-RKY01; psql/pg_dump/pg_restore 16.15. Fontes e módulos originais v0.6.5 preservados, incluindo engine CRLF; helper v0.6.7 adicionado ao deployment original.

Origem: `canca_p01_lab_r1` e `/var/lib/canca/postgres-lab/P01-PG-R1-06230404e329/server-store`.
Destino: `canca_p01_restore_r1`, criado de template0 com owner canca_lab_admin, e
`/var/lib/canca/postgres-recovery/P01-PG-RECOVERY-ZXbAp043/restored-store`.

Captura original: `source-proof/P01-PG-RECOVERY-304b66d3aa73/snapshot.json` dentro do diretório de recuperação.
SHA256 lógico: `13e1473ceab9f6e636ac1709db455ac34a8377b8b63c5e889d86a534685d3fb8`.
Dump custom: `database.dump`; SHA256 exibido ao final:
`5e8ad73f630bb6d41cb8db41aa61e05c9aeefa3f4395733d2fbcab68fa976d8d`.

`capture` revalidou fontes/projeções. Dump, listagem do archive e cópia privada do store executados.
Primeiro verify na base origem com store copiado passou; esse caso sozinho não era restore.
Em seguida, CREATE DATABASE e pg_restore no destino com single-transaction/exit-on-error/no-owner/no-privileges.
Verify **na base destino** passou: 14 tabelas, 20 arquivos e o mesmo snapshot SHA; source_bytes_revalidated=true.
Relatório recuperado: registered/revisão 0, 2 imports, 1 CAS/2 observações, 4 avaliações,
2 finding/2 no_finding, 2 ocorrências históricas Open e catálogo/engine original.

Replay index/assets/findings dos dois bundles no destino: already_indexed/already_projected.
Verify final novamente PASS com o mesmo SHA, 14 tabelas/20 arquivos. PGPASSWORD removida ao final.
As flags database_mutated=false/store_mutated=false são do helper de comparação; CREATE/restore foram ações explícitas separadas.

## Capturas

| Captura 20261002 | Evidência |
|---|---|
| 204541 | Cópia exclusiva recusou arquivo existente; hashes iguais nas duas cópias do helper, utilitários 16.15 |
| 205038 | Conexão origem explícita, diretório novo, snapshot e SHA/14 tabelas/20 arquivos |
| 205419 | Referência encontrada e SNAPSHOT OK |
| 205551 | Dump custom, checksum/lista e cópia; verify origem + store copiado |
| 205808 | CREATE DATABASE, restore destino, verify destino PASS e início do relatório |
| 205817 | Final do relatório: avaliações negativas/positivas, Open, has_more=false |
| 210457 | Seis replays idempotentes, verify final destino PASS, dump SHA e unset PGPASSWORD |

## Limites

Evidência visual, sem recebimento do dump, snapshot JSON original ou logs brutos do host.
Sem RTO/RPO, retenção, disaster recovery de produção, ownership/grants completos ou TLS remoto.
A identidade administrativa permanece registered/revisão 0; transições e cursor/fence completos
serão exercitados separadamente na base recuperada. O store da API ativa não foi parte do roteiro.
FileExistsError foi recusa esperada de overwrite; hashes iguais permitiram usar o helper já presente.
O checksum do snapshot não autentica dados contra alteração deliberada por DBA.

[Próximo roteiro](../LAB_POSTGRESQL_LIFECYCLE_R1_v0.6.8.md).
