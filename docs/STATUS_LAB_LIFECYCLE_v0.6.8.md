# Cancã — status v0.6.8

Recuperação sintética R1: **LAB VALIDATED no Rocky/PostgreSQL 16.15**.
[Sete capturas e limites](validation/POSTGRESQL_P01LAB_RECOVERY_R1_v0.6.7.md).

Lifecycle/paginação R1: **CANDIDATE para LAB**. Helper reutiliza APIs canônicas, com inspect somente leitura
e exercício explícito limitado à base recuperada. Retomada por prefixo conhecido, quatro transições,
replay, três conflitos esperados, paginação e invalidação de cursor. Compara sources/store/12 tabelas
contra referência original; gera proof privado sem dados brutos ou secrets.

Dois testes boundary e quatro de DB real: execução/replay, retomada parcial, história/source drift,
duplicação de páginas e mutação de finding. Qualificação no commit exato registrada na entrega.
Sem migração ou alteração dos módulos de produto; helper novo preserva deployment CRLF original.

TLS remoto, roles completos, API autenticada/UI e restante da Product Alpha permanecem separados.
[Roteiro](LAB_POSTGRESQL_LIFECYCLE_R1_v0.6.8.md) · [ADR 0019](ADR_0019_LAB_Lifecycle_Pagination_v0.6.8.md).
