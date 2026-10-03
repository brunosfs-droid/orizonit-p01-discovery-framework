# Cancã — status v0.6.8

Recuperação sintética R1: **LAB VALIDATED no Rocky/PostgreSQL 16.15**.
[Sete capturas e limites](validation/POSTGRESQL_P01LAB_RECOVERY_R1_v0.6.7.md).

Lifecycle/paginação R1: **LAB VALIDATED no Rocky/PostgreSQL 16.15**. Helper reutiliza APIs canônicas, com inspect somente leitura
e exercício explícito limitado à base recuperada. Retomada por prefixo conhecido, quatro transições,
replay, três conflitos esperados, paginação e invalidação de cursor. Compara sources/store/12 tabelas
contra referência original; gera proof privado sem dados brutos ou secrets.

Dois testes boundary e quatro de DB real: execução/replay, retomada parcial, história/source drift,
duplicação de páginas e mutação de finding. Qualificação no commit exato registrada na entrega.
Sem migração ou alteração dos módulos de produto; helper novo preserva deployment CRLF original.

Capturas 215506/215725/215911: envio do helper do merge ec78a2bb5c08142aa197074c8797082dd61a3ae2,
tar SHA igual nos dois hosts e engine original preservado. Caminho da referência no roteiro
foi transcrito incorretamente; REFERENCIA OK ausente, inspect/exercise recovery_invalid antes da
conexão. Nenhuma transição demonstrada. Etapa 2 corrigida localiza referência por SHA/sidecar e
recusa ausência/ambiguidade; etapa 3 depende do inspect PASS. Não repetir instalação ou restore.

TLS remoto, roles completos, API autenticada/UI e restante da Product Alpha permanecem separados.
[Roteiro](LAB_POSTGRESQL_LIFECYCLE_R1_v0.6.8.md) · [ADR 0019](ADR_0019_LAB_Lifecycle_Pagination_v0.6.8.md).

## Aceite após capturas 230051/230214/230308/230539

Localização automática PASS; inspect registered/revisão 0, primeiro exercise
0→4/completed com quatro transições/quatro rejeições de cursor, replay 4→4 sem
transição. Ambos exit 0; quatro replays idempotentes e três conflitos esperados,
quatro páginas/quatro avaliações, 2 findings/1 CAS, 12 tabelas invariantes e sources/store
preservados. [Aceite e limites](validation/POSTGRESQL_P01LAB_LIFECYCLE_R1_v0.6.8.md).
As falhas anteriores são históricas e não bloqueiam este aceite. Não repetir R1.

## Exportador: correção e tentativa R1

PR #106 integrado: head 361ff2b78e47ecc23d57d13f7b86a497ab184490, merge
d1b32cf6d6185e87fc4a08abb57654c29d8e8c4b, tree 61ffa3745c5b16acc9be52d8aa6d175f55d195ef
igual à qualificada. Python 360 casos (263 PASS/97 skips), PostgreSQL 16/17 156 PASS
por versão e quatro jobs nativos PASS na primeira tentativa. Corrige escape de
URLs no Markdown, sem migração ou alteração do engine.

Capturas 235251/235559/235634/235648: instalação rejeitou entrada de pasta no TAR;
exportação bloqueada por readiness false. Sem resultado exported/PASS. O gate do
exportador continua CANDIDATE, lifecycle/paginação e recuperação permanecem LAB VALIDATED.
[Roteiro corrigido](LAB_POSTGRESQL_EXPORT_R1_v0.6.9.md) e
[diagnóstico](validation/POSTGRESQL_P01LAB_EXPORT_ATTEMPT_R1_v0.6.9.md).
