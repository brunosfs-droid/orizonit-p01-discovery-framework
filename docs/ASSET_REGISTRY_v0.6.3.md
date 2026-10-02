# Registro persistente de assets — v0.6.3

**CANDIDATE para LAB**, Product Alpha, 02/10/2026 (-03), refs #63.
[ADR 0014](ADR_0014_Persistent_Assets_v0.6.3.md).

## ID central e escopo

`cas-<32 hex>` identifica o registro persistido pelo servidor. O ID `ast-<16 hex>`
do resolver é preservado como `source_asset_id`, mas não é chave global: deriva
do seed de identidade e pode se repetir. O ordinal identifica cada observação
dentro do bundle, inclusive quando dois assets do resolver têm o mesmo ID local.

O escopo de correlação é **assessment_id**. Imports de diferentes runs/nodes no
mesmo assessment podem compartilhar ID central quando os sinais permitirem.
Assessments diferentes não são correlacionados automaticamente, mesmo com sinais
idênticos. Continuidade entre assessments depende de futuro modelo explícito de
ambiente/cliente; essa limitação impede misturar contextos que ainda não têm tenancy.

IDs centrais são aleatórios na primeira gravação e permanecem persistidos. Replay
não gera outro ID. Bases independentes não produzem os mesmos IDs a partir do mesmo
bundle; backup/restore do registro importa para a continuidade desses IDs.

## Fonte e política de associação

`project-import` revalida recibo, hashes, identidade, raw bundle e artefatos antes
de conectar. Uma cópia privada do bundle é vinculada ao SHA256 verificado; apenas
JSONs inventariados são extraídos para diretório temporário. O resolver offline
é reexecutado sem escrever no store. JSON de resolver embutido ou processed não
determina a identidade central. Nenhuma coleta, autenticação ou rede é executada.

| Sinal | Papel na correlação |
| --- | --- |
| serial_number não genérico | Forte, somente de fonte credentialed bem sucedida e collected |
| ssh_host_key_sha256 válido | Forte, com base64 case-sensitive original preservado |
| FQDN coletado em identidade credentialed | Corroborador qualificado |
| IP, hostname, FQDN e MAC de Network Discovery | Contexto/candidato; não bastam para associação automática |

Associação automática exige um único candidato, um sinal forte coincidente e duas
categorias qualified coincidentes **na mesma observação anterior aceita**. Exemplos:
serial+FQDN, SSH+FQDN, serial+SSH. Divergência em uma categoria forte bloqueia a
associação, ainda que outras duas coincidam. IP reutilizado, serial sozinho,
hostname/IP sem sinal forte ou candidatos múltiplos ficam para revisão.

Conflitos/ambiguidades locais, múltiplos valores qualificados da mesma categoria
ou IDs locais duplicados também bloqueiam associação automática. Quando não há
candidato, cria-se um novo ID; `insufficient_identity` indica que ele é provisório.
Revisões recebem ID provisório separado e conservam os candidatos, sem fundir
registros ou incorporar seus sinais à busca de candidatos aceitos.

| decision / reason_code | Significado |
| --- | --- |
| new_asset / new_identity | Primeiro registro com sinais suficientes e sem candidato |
| new_asset / insufficient_identity | Registro provisório, com identidade insuficiente |
| linked / corroborated_identity | Nova observação associada a ID persistido |
| review_required / local_conflict | Conflito, ambiguidade ou duplicidade local |
| review_required / strong_conflict | Categoria forte diverge do candidato |
| review_required / uncorroborated_candidate | Candidato existe, mas não há dois sinais qualificados suficientes |
| review_required / multiple_candidates | Mais de um candidato; nenhum escolhido |
| review_required / candidate_bound_exceeded | Mais de 100 candidatos; lista truncada explicitamente |
| review_required / history_bound_exceeded | Mais de 100 observações aceitas no candidato; revisão conservadora |

As associações são explicáveis por sinais e referências de fonte, não uma garantia
de identidade física. Clones podem copiar serial/FQDN/chaves. Não há promoção manual,
merge, relink ou revisão automática de decisões antigas nesta versão; preserve os
dados para o próximo mecanismo de resolução explícita. Não remova registros ou
reescreva evidências para forçar uma associação.

## Operação explícita em base isolada

Use Python 3.12+ e PostgreSQL 16/17, driver/configuração externos do
[guia PostgreSQL](../persistence/README.md), com TLS remoto verify-full. Não é um
pedido de instalação no P01LAB agora; qualificação de servidor terá roteiro próprio.

Conta de DDL: backup/restore deve ser preparado antes da adoção de schema novo.
Migrações 0001/0002 permanecem intactas; `migrate` aplica só o sufixo ausente e registra
hashes. Migração 0003 não fabrica associações para imports existentes:

```sh
python persistence/P01_PostgreSQL.py migrate
```

Retorna `migration: 3`, e replay `already_migrated`. Índice do código novo aceita
schema 1/2/3 verificado; lifecycle aceita 2/3; registro de assets exige 3.
Binários anteriores com lista menor de migrações rejeitam schema 3. Não há downgrade
automático; restauração exige backup e binário compatível. API não migra no startup.

Primeiro indexe um import verificado com a conta indexadora; depois projete com a
conta autorizada de assets. Substitua paths e IDs por valores reais do recibo:

```sh
python persistence/P01_PostgreSQL.py index-import --store-dir /caminho/store-lab --import-dir /caminho/store-lab/assessments/LAB-001/imports/bnd-XXXXXXXXXXXXXXXXXXXX
python persistence/P01_Asset_Registry.py project-import --store-dir /caminho/store-lab --import-dir /caminho/store-lab/assessments/LAB-001/imports/bnd-XXXXXXXXXXXXXXXXXXXX
python persistence/P01_Asset_Registry.py show-import --bundle-id bnd-XXXXXXXXXXXXXXXXXXXX --limit 100
python persistence/P01_Asset_Registry.py show-asset --assessment-id LAB-001 --asset-id cas-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Primeira projeção `projected`; mesma fonte/política `already_projected`. Uma
transação grava todos os IDs/observações/sinais ou nenhum deles. Lock por assessment
serializa bundles concorrentes; timeout lock 5s/statement 30s, sem retry. API de
ingestão v0.6.1 continua indexando só metadados; não executa project-import.

Consultas retornam `found`/`not_found` e não gravam dados. `show-import` pagina
observações: continuar com `--after-ordinal N`, usando `next_after_ordinal` enquanto
`has_more`. Páginas têm limite 1..100; estado/projeção não muda no replay.
`show-asset` mostra contagem de observações e até 100 sinais com flag de truncamento.
Proveniência detalhada fica em `show-import`: role/path/hash/tamanho de cada artefato
e caminhos das fontes de cada sinal. O store conserva os bytes de evidência.

Erros fixos em JSON e exit 2: `import_required` quando metadados ainda não foram
indexados; `import_conflict` se fonte e índice divergem; `asset_projection_conflict`
se a projeção já persistida difere; erros de integridade/schema/configuração e
`database_failed` quando banco falha. Sucesso/not_found retorna exit 0. Resolver
legado limita cobertura; fontes não suportadas retornam `asset_input_invalid`.
Nenhuma exceção do driver, senha ou DSN entra na resposta. A API interna exige
`prepare_assets` para estabelecer proveniência; hashes isolados não autorizam origem.

## Permissões e limites

Role de assets separada: USAGE no schema, SELECT em `schema_migrations` e `imports`,
SELECT/INSERT em `assets`, `asset_imports`, `asset_observations`, `asset_signals`.
Sem UPDATE/DELETE/CREATE. Indexador e operador de lifecycle mantêm suas permissões.
Essas roles são confiáveis; SQL direto e DBA não são impedidos pela aplicação de
fabricar metadados. Não há RBAC de produto nem endpoint remoto de controle de assets.

Metadados de nomes, serial, fingerprint e caminhos relativos podem ser confidenciais.
JSONs de fonte: 16 MiB cada/64 MiB total; até 10.000 assets e 64 sinais por asset.
Esses são limites defensivos, não benchmark de escala. Fonte e runtime/resolver
permanecem no contrato anterior; schema de bundles não mudou.

CI PostgreSQL real usa dados sintéticos e base efêmera. P01LAB PostgreSQL de
roles/TLS/backup/restore, correlação entre assessments, revisão manual, findings e
UI continuam etapas independentes. `CANCA_TEST_POSTGRES=1` apaga schema de teste;
nunca use em banco do LAB ativo ou de cliente.
