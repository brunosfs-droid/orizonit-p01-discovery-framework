# P01 — Status técnico v0.6.5

Status: **LAB VALIDATED — R1 básico sintético; escopo restante CANDIDATE**. Incremento de relatório consolidado da Product Alpha.

CLI somente leitura consolida lifecycle, assets, cobertura de fontes/regras e
ocorrências históricas. Expõe imports ainda sem projeção, catálogos/hashes e
paginação com conflito de escopo se os dados mudarem. Não escolhe uma coleta
latest nem suprime findings antigos. Sem migração nova ou alteração do runtime.

Verificação prevista: testes de fronteira e PostgreSQL 16/17 real com escopo entre
assessments, dados pendentes, fonte insuficiente/sem suporte, paginação, mudanças
de lifecycle/import, escritor concorrente, limites e role reader. CI e qualification
do servidor LAB são gates distintos. Nenhum diagnóstico do host bloqueia este código.

O diagnóstico e a instalação posterior do Rocky foram recebidos. A API existente
continua fora do escopo, com store /root/p01/store-v05e-r1. Backup/restore do par
banco/store passou no CI v0.6.6; v0.6.7 prepara comparação somente leitura para
a recuperação operacional no LAB. Contratos de API autenticada/UI terão incrementos próprios.

[Guia](ASSESSMENT_REPORT_v0.6.5.md) · [ADR](ADR_0016_Assessment_Report_v0.6.5.md).

Fixture offline e [roteiro LAB R1](LAB_POSTGRESQL_R1_v0.6.5.md) preparados para
PostgreSQL 16 nativo, com limite de conexões/memória e store novo. Etapas 1–6 do R1 básico demonstradas pelo operador; não repetir instalação.
A recuperação operacional tem roteiro novo sem modificar a API ativa.

## Atualização de qualificação em 02/10/2026

O R1 básico em PostgreSQL 16.15 no Rocky passou: migração/replay, dois imports,
1 CAS/2 observações, 4 avaliações/2 findings históricos Open e leitura por reader
com UPDATE negado. [Aceite e 18 capturas](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md).
A observação nova substitui a pendência inicial de instalação e fixture. Não
qualifica API com índice, transições lifecycle, cursor/fence completo, TLS remoto,
roles de escrita separados ou restore operacional. Próximo gate: [recuperação R1](LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md).
