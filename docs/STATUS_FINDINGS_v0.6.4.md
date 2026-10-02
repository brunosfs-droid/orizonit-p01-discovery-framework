# P01 — Status técnico v0.6.4

Status: **CANDIDATE para LAB**. Incremento findings/proveniência, Product Alpha.

Entregue: adaptador de duas regras WinRM, catálogo e engine vinculados por SHA256,
source refs ao raw bundle verificado, cobertura explícita, análise e ocorrências
imutáveis, replay, conflitos, ligação conservadora ao registro de assets e leitura
paginada. Migração 0004 explícita, sem backfill ou alteração de 0001–0003.
Nenhuma avaliação ausente implica ausência de risco; nova coleta não fecha findings.

Validação: testes locais/source e integração PostgreSQL 16/17 no CI são requisitos
para integração deste incremento. Casos de banco usam bases descartáveis sintéticas,
não o store/servidor do P01LAB. Qualificação de roles, TLS e backup/restore no LAB
continua independente. Runtime/scheduler e Analyzer legado não são alterados.

Próximo trabalho independente: preparo de qualificação do servidor PostgreSQL,
backup/restore consistente do banco + store e consultas de relatório com cobertura
explícita. Triagem manual, contratos de API autenticada e UI seguem incrementos
próprios. Nenhum novo teste de scheduler ou AUTH/FULL/POST é necessário para este
incremento. Não instalar PostgreSQL no LAB sem roteiro de base isolada.

[Guia](FINDINGS_v0.6.4.md) · [ADR](ADR_0015_Findings_v0.6.4.md) ·
[Próximos passos](NEXT_STEPS_v0.6.0.md).
