# ADR 0016 — Relatório consolidado e cobertura explícita

Data: 02/10/2026. Aceito antes da implementação v0.6.5 CANDIDATE.

## Problema

Os comandos atuais consultam um import, asset ou lifecycle separadamente. Um
assessment pode conter imports sem assets/análises e findings antigos mesmo após
uma coleta sem findings. O relatório precisa expor essas diferenças sem inferir
conclusão, ausência de risco, identidade confirmada ou remediação.

## Decisão

Adicionar CLI show-assessment somente leitura, consolidando todas as observações
persistidas do assessment. Sem migração nova, recálculo de regras, leitura de raw
bundles, coleta, remediação, escolha automática de latest ou supressão de histórico.
Schema exige prefixo conhecido 0001–0004. Estado/revisão administrativo, número de
imports, imports sem assets/análise, IDs/decisões de identidade, outcomes por regra
e ocorrências Open são apresentados separadamente. Catálogos/engines originais
vêm das análises persistidas, com seus hashes. Não chamar o assessment de limpo
ou completo por ausência de findings; no_finding tem escopo da seção avaliada.

Cada invocação usa uma transação REPEATABLE READ READ ONLY. Até 100 imports,
10.000 observações e 10.000 avaliações no assessment; excesso rejeita o relatório
inteiro com report_limit_exceeded. Não mostrar um resumo truncado como completo.
Counts e detalhes são do mesmo snapshot. Timeout de statement/lock do conector;
nenhum benchmark ou promessa para assessments ilimitados.

Paginar avaliações por (analysis_id, ordinal), 1–100 por página. Hash de escopo
vincula lifecycle, conjunto de imports/projeções/análises/catálogos, associação
de observações e contagens. Depois da primeira página, exigir expected_scope_sha256.
Mudança normal de dados entre invocações produz report_scope_conflict: recomeçar
o relatório, sem misturar páginas. Sem token de snapshot durável ou proteção
contra DBA que altere registros/hashes diretamente. Report timestamp não entra
no hash e não é clock de avaliação das regras.

Indicar source_bytes_revalidated=false: esse relatório lê metadados anteriormente
verificados, não reaudita o filesystem. Conservar source_path/source_sha256 e
referências JSON, rule_id, occurrence ID, evidence pequena, CAS e decisão quando
há observação única. Ambiguous/unresolved não seleciona CAS. Provisório/review
permanece nessa condição. Findings de vários runs são ocorrências distintas;
não contá-los como vulnerabilidades únicas ou encontrar delta/fechamento implícito.

## Validação e fronteira

CLI valida identificadores/cursor antes da conexão e redige erros por códigos
fixos. Role reader: USAGE/schema e SELECT nas tabelas consultadas, sem INSERT,
UPDATE, DELETE ou DDL. Sem endpoint remoto, RBAC multi-tenant ou UI.
Role/SQL internos continuam confiáveis. LAB PostgreSQL é independente e não
bloqueia esse incremento de código/CI.

Testar PostgreSQL 16/17: assessment vazio/desconhecido; imports sem projeção;
vários runs com findings antigos preservados; auth/SSH/section outcomes; escopo
entre assessments; paginação/fence após novos imports ou lifecycle; consistência
com escritor concorrente; limites; catálogos originais; schema drift e reader.
