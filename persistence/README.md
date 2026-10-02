# PostgreSQL metadata foundation — v0.6.3

**CANDIDATE para LAB.** Primeiro incremento da Product Alpha (issue #63).
O core portátil permanece v0.5e.6 e o scheduler v0.5f.3 continua independente.

Este componente indexa explicitamente os metadados de **um import já existente
no store de arquivos**. Antes de conectar, verifica recibo/SHA256, localização,
identidades, uma cópia privada do bundle, contrato canônico, hashes internos e
bundle ID derivado. Não executa discovery, autenticação, upload ou reprocessamento.
O store continua sendo a fonte dos bytes de evidência. O PostgreSQL recebe IDs,
hashes, caminhos relativos, roles, tamanhos e timestamps; não recebe os arquivos.

## Instalação isolada

Python 3.12+, PostgreSQL 16 ou 17. Driver opcional:

```sh
python -m pip install -r persistence/requirements-postgres.txt
```

Configure `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER` e credenciais por mecanismo
externo do libpq, preferencialmente `PGPASSFILE`. Não passe DSN/senha na linha de
comando, não publique arquivos de credenciais e não use banco de cliente nos testes.
`PGSERVICE` não é aceito; a configuração de host/banco/usuário deve ser explícita.
Conexões remotas impõem `sslmode=verify-full` e precisam de CA/certificado e nome
válidos (`PGSSLROOTCERT` quando necessário). Loopback/socket local permite a
configuração local do libpq, conforme a política do host.

Com uma **base de LAB dedicada**, primeiro com uma conta autorizada para DDL:

```sh
python persistence/P01_PostgreSQL.py migrate
```

Resultado: `migrated`, depois `already_migrated`, `migration: 4`. Migrações 0001,
0002, 0003 e 0004 são transacionais e seus SHA256 ficam registrados. Aplica-se somente
o sufixo ausente de uma sequência válida. 0002 inicia assessments existentes em
registered/revisão 0; 0003 não infere associações de assets e 0004 não cria análises por inferência. Versão/checksum divergentes bloqueiam a operação.
Não há downgrade ou reparo automático de schema.

Com uma conta indexadora separada, configurada pelo administrador com `USAGE`
no schema, `SELECT` em `canca.schema_migrations` e `SELECT, INSERT` em
`canca.assessments`, `canca.nodes`, `canca.runs`, `canca.imports` e
`canca.artifacts`:

```sh
python persistence/P01_PostgreSQL.py index-import --store-dir /caminho/store --import-dir /caminho/store/assessments/LAB-001/imports/bnd-XXXXXXXXXXXXXXXXXXXX
python persistence/P01_PostgreSQL.py show-import --bundle-id bnd-XXXXXXXXXXXXXXXXXXXX
```

Substitua caminhos e bundle ID pelos **valores reais do recibo**, não pelos
placeholders acima. Não é necessário conceder UPDATE, DELETE ou CREATE à conta
indexadora. O administrador deve configurar separadamente TLS, autenticação,
backup e acesso ao filesystem. Não há RBAC de produto nesta versão.

## Contrato

- Uma transação grava assessment, node, run, import e artefatos juntos.
- Mesmo bundle/projeção: `already_indexed`; projeção diferente: `bundle_conflict`,
  exit 2, preservando o registro anterior. O índice não substitui recibos.
- Advisory lock por bundle serializa escritores; lock de migração serializa DDL.
- Timeout de lock 5s e statement 30s; sem retry ou recuperação automática.
- `show-import`: `found` ou `not_found`, exit 0.
- Falhas retornam somente códigos fixos em JSON e exit 2. Exceções do driver,
  credenciais, DSN e caminhos não são impressos.
- `index_import(conn, projection)` é API interna de confiança; callers devem
  usar `prepare_import`. Um hash isolado não comprova origem ou autorização.

## Validação e limites

O CI usa serviços efêmeros PostgreSQL 16/17 e dados sintéticos: migração/replay,
rollback, conflito, concorrência, papel indexador sem privilégios de mutação,
consulta e falha sem schema. Os testes de source rodam sem driver/banco.
`CANCA_TEST_POSTGRES=1` habilita testes que **apagam o schema canca** da base
configurada; destina-se exclusivamente ao serviço efêmero de CI.

A API v0.6.1 oferece integração opt-in (`--metadata-index postgres`), default off;
ver [contrato e reconciliação](../docs/INGESTION_INDEX_v0.6.1.md). Identidade persistente de
findings, UI, backup/restore e qualificação de um
servidor PostgreSQL no LAB pertencem às próximas etapas. PostgreSQL 18 ainda não
está na matriz validada desta versão.

A v0.6.2 adiciona [lifecycle administrativo](../docs/ASSESSMENT_LIFECYCLE_v0.6.2.md)
por CLI separada. Indexação do código novo aceita schema 1/2/3 verificado; lifecycle
exige pelo menos 2. Imports não alteram o lifecycle existente. A conta indexadora continua sem
UPDATE/DELETE; a conta de lifecycle recebe permissões próprias. Binários antigos
com lista menor de migrações rejeitam schema mais novo; backup/restore é necessário para retornar.

A v0.6.3 adiciona [registro de assets](../docs/ASSET_REGISTRY_v0.6.3.md), com CLI
`P01_Asset_Registry.py project-import/show-import/show-asset`. Exige schema 3 e import
indexado. Escopo assessment, ID central próprio e proveniência; ambiguidades não
são fundidas. API não projeta assets automaticamente. A role de assets possui
permissões separadas de SELECT/INSERT, sem UPDATE/DELETE/CREATE.

[ADR](../docs/ADR_0011_PostgreSQL_Foundation_v0.6.0.md) ·
[Status](../docs/STATUS_PERSISTENCE_v0.6.0.md) ·
[Orientação de próximos passos](../docs/NEXT_STEPS_v0.6.0.md)

## Findings v0.6.4

Análise explícita de evidência WinRM, cobertura e ocorrências imutáveis.
[Guia](../docs/FINDINGS_v0.6.4.md) e [ADR](../docs/ADR_0015_Findings_v0.6.4.md).
Migration 0004 não reescreve 0001–0003 nem faz backfill.

## Relatório v0.6.5

[CLI somente leitura](../docs/ASSESSMENT_REPORT_v0.6.5.md) consolida assessments
com cobertura e ocorrências históricas. Sem migração nova; schema mínimo 4.

## Exportação v0.6.9

[Exportação consolidada somente leitura](../docs/REPORT_EXPORT_v0.6.9.md) reutiliza
a consulta v0.6.5: JSON completo, Markdown e hashes em diretório privado novo.
Sem migração, escrita SQL ou leitura do store; mesmas permissões SELECT do relatório.
