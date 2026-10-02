# P01 — Status técnico v0.6.5

Status: **CANDIDATE para LAB**. Incremento de relatório consolidado da Product Alpha.

CLI somente leitura consolida lifecycle, assets, cobertura de fontes/regras e
ocorrências históricas. Expõe imports ainda sem projeção, catálogos/hashes e
paginação com conflito de escopo se os dados mudarem. Não escolhe uma coleta
latest nem suprime findings antigos. Sem migração nova ou alteração do runtime.

Verificação prevista: testes de fronteira e PostgreSQL 16/17 real com escopo entre
assessments, dados pendentes, fonte insuficiente/sem suporte, paginação, mudanças
de lifecycle/import, escritor concorrente, limites e role reader. CI e qualification
do servidor LAB são gates distintos. Nenhum diagnóstico do host bloqueia este código.

Diagnóstico do P01-LNX-RKY01 recebido em 02/10/2026: Rocky 10.2, Python 3.12.13,
RAM 1 GiB/~648 MiB available, swap 2,3 GiB sem uso, raiz com 26 GiB livres;
psql/pg_dump/pg_restore ausentes no PATH e zero units PostgreSQL listadas.
API existente roda com store /root/p01/store-v05e-r1. Isso não prova ausência de
instalação versionada/container fora do PATH. LAB deverá usar base e store isolados.
Nenhuma instalação, migração ou mudança da API ativa foi executada aqui.

Próximo desenvolvimento independente: fixture e validação de backup/restore do
par banco/store, seguida dos contratos de consulta/API autenticada. UI e triagem
manual terão incrementos próprios. O trabalho segue com autonomia; confirmação
só é necessária para decisões reais ou execução/validação que dependa do LAB.

[Guia](ASSESSMENT_REPORT_v0.6.5.md) · [ADR](ADR_0016_Assessment_Report_v0.6.5.md).

Fixture offline e [roteiro LAB R1](LAB_POSTGRESQL_R1_v0.6.5.md) preparados para
PostgreSQL 16 nativo, com limite de conexões/memória e store novo. Primeira execução
solicitada ao operador: etapas 1–3, sem modificar a API ativa.
