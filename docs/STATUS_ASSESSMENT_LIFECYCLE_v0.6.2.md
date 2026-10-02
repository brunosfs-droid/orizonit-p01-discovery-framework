# Cancã v0.6.2 — Lifecycle do assessment

Data: 02/10/2026 (-03). **CANDIDATE para LAB**, incremento Product Alpha, refs #63.

Implementado: estados administrativos `registered`, `active`, `review_required`,
`completed`, `cancelled`; transições explícitas por CLI; revisão otimista, row lock,
request ID idempotente, eventos transacionais e consulta paginada consistente.
Backfill neutro em migração 0002 explícita, preservando imports existentes e SQL
0001. Import/registro não concluem nem reabrem assessments automaticamente.

O runtime permanece v0.5e.6; scheduler/hosts v0.5f.3; API/bridge v0.6.1, API v1.
A fundação PostgreSQL passa para v0.6.2 e aceita prefixos verificados de migração
1/2 para imports; lifecycle exige migração 2. Nada migra no startup.

Validação: contratos locais e testes em PostgreSQL 16/17 no workflow PostgreSQL
CI, incluindo upgrade com dados, rollback, concorrência, replay após avanço,
estado terminal, leitura e role com histórico sem UPDATE/DELETE. Resultados do
commit exato constam no PR de integração e no relatório de CI da entrega.

`completed` é declaração administrativa, não comprovação de cobertura. Sem RBAC
de produto/API administrativa/UI; actor_ref declarado, autorização externa por
contas/roles PostgreSQL. Histórico append-only na aplicação, modificável por DBA.
Qualificação PostgreSQL P01LAB (TLS/roles/backup/restore) permanece pendente.

[ADR 0013](ADR_0013_Assessment_Lifecycle_v0.6.2.md) ·
[Guia](ASSESSMENT_LIFECYCLE_v0.6.2.md) ·
[Soak estendido aprovado](validation/SCHEDULER_P01LAB_EXTENDED_v0.5f.3.md)
