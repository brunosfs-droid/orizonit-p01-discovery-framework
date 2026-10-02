# PostgreSQL P01LAB R1 básico — aceite limitado

Data: 02/10/2026 (-03). **LAB VALIDATED no escopo básico sintético**, demonstrado por 18 capturas do operador. Não é aceite de toda a Product Alpha.

Host P01-LNX-RKY01, Rocky 10.2, PostgreSQL 16.15 AppStream, Python 3.12.13/psycopg 3.3.6. Pacotes e cluster ausentes na verificação inicial; instalação nova. Serviço active/running e disabled (start manual), escuta 127.0.0.1:5432; shared_buffers 64MB, max_connections 10. Captura após startup mostra 646MiB disponíveis de 1GiB e swap sem uso. Isso é observação pontual, não sizing/soak.

Código enviado por git archive do merge **a334f6ef0d66805d71b7f411d4f7981f53df0655** (v0.6.5), em `/root/p01/canca-postgres-lab-v0.6.5`. O Windows já estava em d162245 (v0.6.6), mas o archive foi explicitamente gerado do merge v0.6.5. Hash SHA256 do tar aparece igual nos dois hosts. venv exclusiva, sem evidência de alteração na API/store ativo `/root/p01/store-v05e-r1`.

Base nova `canca_p01_lab_r1` a partir de template0, owner `canca_lab_admin` NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION; reader separado. Senhas informadas em prompts ocultos. HBA final demonstra SCRAM para as duas bases LAB antes da regra geral reject IPv4, sem erro de parsing; local peer preservado. Uma edição inicial posicionou as regras depois de ident; foi corrigida e reload demonstrado.

Fixture: `/var/lib/canca/postgres-lab/P01-PG-R1-06230404e329/server-store`, assessment `P01-PG-LAB-R1`. Dois bundles: `bnd-02516d3a352079354e81` e `bnd-9a8b74bf9b09d8bfedba`. Migração 4 retornou migrated e replay already_migrated. Cada import indexou 4 artefatos e projetou 1 observação/2 avaliações. Primeiro import: new_asset e 2 findings; segundo: linked e 0 findings. Replay de ambos: already_indexed/already_projected, com IDs e contagens apresentados preservados.

Relatório como admin (--limit 1) e reader (--limit 100): registered/revision 0, 2 imports/2 análises/2 fontes credentialed avaliadas, 1 CAS, 2 observações, 4 avaliações, 2 finding e 2 no_finding, 2 ocorrências históricas Open. Report scope SHA igual nas duas consultas; leitura completa sem has_more. Nenhuma ausência inferida como remediação.

Reader recebeu somente USAGE/SELECT nas tabelas do relatório; consulta passou e `UPDATE canca.findings SET status='Open'` foi negado. **A negação é o resultado esperado.** Grants mostrados mais a negação demonstram esse caso; não representam auditoria completa de todas as permissões.

## Mapa das capturas

| Captura (20261002) | Evidência |
|---|---|
| 192121 | Ausência inicial e instalação AppStream 16.15 |
| 192648 | HBA inicial ainda depois de ident |
| 192715 | Include no postgresql.conf |
| 192725 | `include` executado no shell falhou; edição via vi em seguida |
| 192844 | Serviço, loopback, parâmetros e memória |
| 192957 | Journal de startup sem falha apresentada |
| 193135 | Git archive do merge v0.6.5, SHA e scp |
| 193239 | SHA Linux, extração, venv e driver |
| 193437 | Roles e base template0 |
| 194521 | HBA final corrigido, reload, parsed rules sem erro |
| 194819 | Conexão admin, migrate/replay, fixture pronta |
| 194858 | Caminhos dos dois imports |
| 195125 | Indexação/assets/findings de ambos |
| 195151 | Replay de ambos |
| 195231 | Relatório paginado, resumo/primeira avaliação |
| 195441 | Grants do reader |
| 195540 | Relatório completo como reader, findings Open |
| 195614 | UPDATE negado e PGPASSWORD removida |

As capturas estão no pacote de evidências com inventário SHA256. Não foram enviados journals/raw JSON do LAB; não tratá-los como recebidos ou auditados. Não foi demonstrada paginação com cursor/fence em várias chamadas, transição lifecycle, TLS remoto, roles separados de escrita, restore operacional, retenção/PITR/HA ou carga prolongada. Backup/restore CI v0.6.6 permanece evidência própria; próxima etapa é o [roteiro de recuperação LAB v0.6.7](../LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md).

O fixture_script_sha256 apresentado (`0f7c981aae31c1427f11eeb7c35373eb2efc72af8239a923756e3af19e2bce2a`) e o engine_sha256 (`57c0b7834095d00512e6046bd884c03556f46738e97d7fdb4dcb9847efcc2365`) correspondem aos arquivos do merge v0.6.5 com finais CRLF. A comparação foi calculada sobre os bytes; não indica mudança semântica. Essa distinção precisa ser preservada na revalidação futura de projeções, cujo engine hash é parte da fingerprint.
