# Cancã — Findings v0.6.4 CANDIDATE

Adaptador offline para evidências WinRM inventariadas em bundles existentes.
Opera explicitamente depois do índice e registro de assets. Não realiza coleta,
autenticação, alterações no store ou fechamento administrativo de findings.

## Cobertura e significado

| Regra | Evidência exigida | Condição |
|---|---|---|
| WIN-FW-001 | auth success, coleta, seção firewall success/status 0, três perfis distintos Domain/Private/Public com booleanos | algum perfil desabilitado |
| WIN-AD-001 | auth success, coleta, seção identity success/status 0, membro de domínio role 1/3, seção secure_channel success/status 0, checked true, healthy booleano | healthy false |

DCs e Windows fora de domínio têm WIN-AD-001 not_applicable quando identity foi
comprovada. SSH é not_supported nas duas regras. As outras 17 regras do Analyzer
v0.2 não fazem parte deste catálogo. JSONs de collectors locais não são inputs
deste CLI; o Analyzer legado permanece independente.

| Resultado | Interpretação |
|---|---|
| finding | ocorrência observada na seção; requer validação antes de remediação |
| no_finding | condição não observada na seção comprovadamente avaliada |
| insufficient_evidence | autenticação/coleta/seção/dados ausentes, falhos ou inválidos |
| not_applicable | regra de secure channel fora de seu escopo comprovado |
| not_supported | protocolo/formato sem adaptador para as regras atuais |

Falhas em outras seções não descartam firewall/secure channel comprovados.
Uma seção repetida, booleano string ou ausência de perfil nunca produz resultado
limpo. Mesmo com no_finding nas duas regras, o assessment não é declarado seguro,
completo ou livre de problemas. WinRM pode ter limites de privilégio/visibilidade.

## Execução explícita em base isolada

Pré-requisitos: Python, driver opcional de persistence/requirements-postgres.txt,
PostgreSQL 16/17, PGHOST/PGDATABASE/PGUSER e autenticação externa aprovada.
Não colocar DSN/senha em comandos, reports ou logs. Sem conexão configurada não
há execução de banco. Hosts remotos usam verify-full no conector existente.

Migração é executada pelo administrador, nunca automaticamente na ingestão:

```bash
python persistence/P01_PostgreSQL.py migrate
```

Resultado esperado: migration 4. 0001–0003 não são reescritas. Defina caminhos
reais do store e import já recebido para as três operações explícitas:

```bash
python persistence/P01_PostgreSQL.py index-import --store-dir "$P01_STORE_DIR" --import-dir "$P01_IMPORT_DIR"
python persistence/P01_Asset_Registry.py project-import --store-dir "$P01_STORE_DIR" --import-dir "$P01_IMPORT_DIR"
python persistence/P01_Findings.py project-import --store-dir "$P01_STORE_DIR" --import-dir "$P01_IMPORT_DIR"
```

Replay da terceira operação retorna already_projected com os mesmos IDs e
contagens. Não gera coleta nem fecha ocorrências anteriores. Fonte inválida é
rejeitada antes da conexão. Import/asset sem projeção ou com drift rejeita toda a
análise; finding_projection_conflict indica conteúdo diferente na mesma versão.
Preserve dados e investigue antes de qualquer nova política. Sem retry/migração
automáticos, relink de assets ou overwrite.

```bash
python persistence/P01_Findings.py show-import --bundle-id "$P01_BUNDLE_ID" --limit 100
```

Consulta retorna catálogo/hashes, contagens totais e avaliações paginadas.
Continue usando next_after_ordinal enquanto has_more=true. Cada avaliação conserva
source_path/source_sha256, referências JSON, rule_id, resultado, finding_id/status
quando positivo e CAS/decisão de identidade quando há uma observação única.
Ambiguous/unresolved conserva asset_id null; review_required continua revisão.
new_asset pode ser provisório por insufficient_identity: o finding não promove
a identidade. Finding status Open é observacional; triagem é incremento posterior.

## Permissões

Exemplo para uma role já provisionada pelo administrador, sem criar credenciais:

```sql
GRANT USAGE ON SCHEMA canca TO canca_analyst;
GRANT SELECT ON canca.schema_migrations, canca.imports, canca.artifacts,
    canca.asset_imports, canca.asset_observations TO canca_analyst;
GRANT SELECT, INSERT ON canca.finding_analyses, canca.finding_evaluations,
    canca.findings TO canca_analyst;
```

Roles de migração, ingestão, assets e lifecycle são independentes. Sem UPDATE,
DELETE ou CREATE para analyst. Role read-only recebe somente SELECT/USAGE.
SQL direto/API interna permanecem acesso confiável; hash não autentica DBA ou
engine. CLI valida fonte e projeções. Evidência bruta fica no store; metadados
e seções extraídas pequenas também precisam de controle de acesso/backup.

Limites: 1.000 fontes credentialed, 2.000 avaliações; 16 MiB/JSON e 64 MiB de
JSON credentialed somados. Não é benchmark nem paginação ilimitada.
Sem correlação inter-assessment, remediação, API remota ou UI neste incremento.

[ADR](ADR_0015_Findings_v0.6.4.md) · [Assets](ASSET_REGISTRY_v0.6.3.md).
