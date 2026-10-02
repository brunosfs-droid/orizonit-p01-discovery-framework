# Cancã — Relatório consolidado v0.6.5

Status: CANDIDATE. CLI somente leitura de metadados persistidos, sem migração nova.
Pode ser desenvolvido/validado no CI independentemente do provisionamento no LAB.

## Primeira página

Com conector PostgreSQL já configurado para uma base isolada com schema 0001–0004:

```bash
python persistence/P01_Assessment_Report.py show-assessment --assessment-id LAB-001 --limit 100
```

O JSON contém lifecycle administrativo, imports sem assets/análise, contagens de
identidade, outcomes por regra, ocorrências de findings, catálogos originais e
avaliações da página. snapshot_at_utc é hora do snapshot do relatório, não a hora
de avaliação do finding. source_bytes_revalidated=false: raw bundles não são
revalidados por este comando. O relatório depende da proveniência antes persistida.

## Leitura correta

| Campo | Significado |
|---|---|
| scope_mode | all_persisted_imports: todas as coletas persistidas do assessment, sem seleção de latest |
| lifecycle | decisão administrativa; completed não comprova cobertura/segurança |
| imports_without_assets / imports_without_analysis | projeções pendentes explícitas |
| credentialed_sources_indexed / evaluated | fontes inventariadas versus fontes com avaliação persistida |
| coverage.by_rule | finding, no_finding, insufficient_evidence, not_applicable e not_supported por regra |
| identity.central_asset_count | IDs centrais registrados; pode incluir provisórios |
| identity.decisions / reasons | revisão, associação e insuficiência de identidade sem promoção |
| recorded_finding_occurrences | ocorrências históricas; não vulnerabilidades únicas nem apenas a coleta mais recente |
| catalogs | catálogo/engine originais de cada conjunto de análises com hashes |
| evaluations | regra e evidência/ref da fonte, CAS/decisão quando aplicável, occurrence ID/status Open |

O catálogo atual tem WIN-FW-001 e WIN-AD-001 de enrichment WinRM. As outras 17
regras do Analyzer legado não são cobertas. SSH continua not_supported. Uma regra
no_finding não declara o host/assessment saudável. all_imports_analyzed indica
somente presença de análise nos imports persistidos; evidência insuficiente pode
ocorrer em todos eles. Assessment sem imports retorna no_imports, não clean.

Findings antigos são preservados após novo run sem findings. Revisão/provisório
não vira identidade confirmada. Não existe triagem, remediação, auto-close, delta,
correlação entre assessments, API remota ou UI neste incremento.

## Próximas páginas

Se has_more=true, copiar report_scope_sha256 e next_cursor da primeira resposta:

```bash
python persistence/P01_Assessment_Report.py show-assessment --assessment-id LAB-001 \
  --after-analysis-id "$P01_AFTER_ANALYSIS_ID" --after-ordinal "$P01_AFTER_ORDINAL" \
  --expected-scope-sha256 "$P01_REPORT_SCOPE_SHA256" --limit 100
```

Cada página conserva o resumo de todo o assessment. Limite afeta apenas detalhes.
Não continuar páginas sem o hash de escopo. report_scope_conflict significa que
imports/projeções/identidade/lifecycle mudaram: descartar o conjunto parcial e
recomeçar da primeira página. Não concatenar páginas com hashes diferentes.
Não há snapshot durável mantido entre processos; o hash detecta mudanças normais
de dados, sem alegar proteção contra alterações diretas de DBA.

Limites por assessment: 100 imports, 10.000 observações, 10.000 avaliações; página
de 1–100. Excesso retorna report_limit_exceeded, sem relatório parcial. Dados
persistidos inconsistentes retornam report_data_conflict; schema drift mantém
schema_mismatch/schema_required. Queries seguem timeouts de lock 5s/statement 30s.
Não é benchmark nem garantia para volumes ilimitados.

## Role somente leitura

Exemplo para role canca_reader já provisionada pelo administrador:

```sql
GRANT USAGE ON SCHEMA canca TO canca_reader;
GRANT SELECT ON canca.schema_migrations, canca.assessments, canca.imports,
    canca.artifacts, canca.assets, canca.asset_imports, canca.asset_observations,
    canca.finding_analyses, canca.finding_evaluations, canca.findings TO canca_reader;
```

O CLI não precisa de INSERT/UPDATE/DELETE/DDL, secrets no JSON ou acesso ao store.
O parâmetro assessment_id é filtro de consulta, não autorização multi-tenant.
Configuração de autenticação/TLS/contas permanece no provisionamento do servidor.

[ADR](ADR_0016_Assessment_Report_v0.6.5.md) ·
[Findings](FINDINGS_v0.6.4.md) · [Assets](ASSET_REGISTRY_v0.6.3.md).
