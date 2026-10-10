# Cancã — LAB PostgreSQL R1 no Rocky

Status: **LAB VALIDATED — R1 básico sintético em 02/10/2026**.
[Aceite](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md). Etapas 1–6 já demonstradas;
não repetir instalação, fixture ou reader. O roteiro abaixo fica como histórico
e referência para instalação nova. Próximo gate: [recuperação R1 v0.6.7](LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md). O diagnóstico recebido em
02/10/2026 mostra P01-LNX-RKY01, Rocky 10.2, Python 3.12.13, RAM 1 GiB/648 MiB
available e 26 GiB livres. Ferramentas PostgreSQL ausentes no PATH e zero units
listadas. API ativa usa /root/p01/store-v05e-r1 e porta 8443.

Este R1 usa PostgreSQL **16 da distribuição**, base canca_p01_lab_r1 e fixture
nova em /var/lib/canca/postgres-lab. Fonte sintética offline, sem coleta ou acesso
aos ativos. Configuração inicial pequena; não é sizing de produção ou benchmark.
Store/API atuais não são inputs deste teste. Serviço PostgreSQL será iniciado
manualmente, sem enable automático ou mudança na API.

**Para instalação nova, o checkpoint inicial é nas etapas 1–3. No P01-LNX-RKY01 já foi aprovado; não repetir.**
As etapas 4–6 já estão preparadas para depois desse checkpoint. Se uma etapa
falhar, preserve a saída e os arquivos; não reinicialize cluster nem apague dados.

## 1. Verificar a instalação disponível no Rocky

Na janela SSH do Rocky, como root:

```bash
rpm -q postgresql-server postgresql16-server postgresql17-server
pgrep -a postgres
ls -ld /var/lib/pgsql/data
dnf info postgresql-server
```

Pacotes não instalados, pgrep sem saída e diretório inexistente são esperados na
instalação nova. Se houver processo/cluster existente, envie a saída para adaptar
o roteiro à instalação real. Não executar initdb sobre instalação existente.
dnf info deve mostrar major 16. Se mostrar outra major, não seguir este roteiro
até identificar a seleção do repositório.

Instalar os pacotes da distribuição:

```bash
dnf install postgresql-server postgresql
psql --version
pg_dump --version
pg_restore --version
```

O dnf mostrará os pacotes antes de instalar; confirmar somente a seleção esperada
PostgreSQL 16. Não adicionar PGDG, container, porta externa ou regra de firewall.

## 2. Inicializar somente o cluster novo

Confira que /var/lib/pgsql/data/PG_VERSION não existe. Se existir, há cluster
inicializado e este passo não se aplica. Com instalação nova:

```bash
postgresql-setup --initdb
cat /var/lib/pgsql/data/PG_VERSION
```

Esperado: 16. A seguir criar arquivo próprio para os parâmetros do LAB:

```bash
cat > /var/lib/pgsql/data/canca-lab.conf <<'CONF'
listen_addresses = '127.0.0.1'
port = 5432
max_connections = 10
shared_buffers = '64MB'
work_mem = '2MB'
maintenance_work_mem = '32MB'
autovacuum_work_mem = '16MB'
effective_cache_size = '256MB'
max_parallel_workers_per_gather = 0
max_wal_senders = 0
autovacuum_max_workers = 1
password_encryption = 'scram-sha-256'
CONF
chown postgres:postgres /var/lib/pgsql/data/canca-lab.conf
chmod 600 /var/lib/pgsql/data/canca-lab.conf
```

Abra postgresql.conf e acrescente ao final **uma vez**:

```text
include = 'canca-lab.conf'
```

Comando para abrir no editor disponível:

```bash
vi /var/lib/pgsql/data/postgresql.conf
```

Em vi: G vai ao fim, o abre linha, inserir include, Esc e :wq salvam. Não alterar
outros parâmetros. Ajustes 64/2/32/16 MB e 10 conexões são escolha conservadora
para esta fixture, não limite global rígido de memória do processo.

Edite o pg_hba.conf **somente deste cluster recém-criado**. Antes das regras host
existentes, acrescente estas duas linhas nesta ordem:

```text
host canca_p01_lab_r1,canca_p01_restore_r1 all 127.0.0.1/32 scram-sha-256
host all all 127.0.0.1/32 reject
```

```bash
vi /var/lib/pgsql/data/pg_hba.conf
```

Preservar as linhas local/peer para administração via usuário postgres. As regras
TCP acima restringem o LAB aos dois nomes de base. listen_addresses aceita apenas
loopback; não há acesso direto pela rede do LAB. TLS remoto e rejeição de CA/hostname
incorretos terão um gate próprio se o banco passar a outro host.

## 3. Iniciar e conferir o serviço

```bash
systemctl start postgresql
systemctl is-active postgresql
ss -lnt | sed -n '/:5432/p'
runuser -u postgres -- psql -h /var/run/postgresql -U postgres -d postgres -X -c "SHOW server_version;"
runuser -u postgres -- psql -h /var/run/postgresql -U postgres -d postgres -X -c "SHOW shared_buffers; SHOW max_connections; SHOW listen_addresses;"
free -h
```

Esperado: active; listener 127.0.0.1:5432; server 16.x; 64MB/10/127.0.0.1.
**Envie essa saída antes de seguir.** Se start falhar, consultar:

```bash
systemctl status postgresql --no-pager
journalctl -u postgresql -n 40 --no-pager
```

Esses logs não devem conter senhas. Não enviar chaves, env ou valores de secrets.
Nenhuma instalação/partida foi executada pelo desenvolvimento; este é o gate do host.

## 4. Preparar a versão qualificada separadamente do Agent

Etapa posterior ao checkpoint 3. No PowerShell do Windows, no repositório:

```powershell
Set-Location C:\GitHub\canca
git pull --ff-only
git rev-parse HEAD
```

Usar o merge SHA publicado no relatório de validação v0.6.5 em $P01Commit:

```powershell
$P01Commit = 'COLE_AQUI_O_MERGE_SHA_QUALIFICADO_V065'
git archive --format=tar --output=C:\Canca\canca-postgres-lab-v0.6.5.tar $P01Commit
Get-FileHash C:\Canca\canca-postgres-lab-v0.6.5.tar -Algorithm SHA256
scp C:\Canca\canca-postgres-lab-v0.6.5.tar root@192.168.100.50:/root/p01/
```

No Rocky, conferir o hash igual e extrair em diretório novo:

```bash
sha256sum /root/p01/canca-postgres-lab-v0.6.5.tar
mkdir /root/p01/canca-postgres-lab-v0.6.5
tar -xf /root/p01/canca-postgres-lab-v0.6.5.tar -C /root/p01/canca-postgres-lab-v0.6.5
cd /root/p01/canca-postgres-lab-v0.6.5
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r persistence/requirements-postgres.txt
```

Diretório já existente: preservar e identificar antes de extrair, sem overwrite.
Não substituir /root/p01/canca-agent-v0.5f.3 nem reiniciar a API.

## 5. Base isolada e fixture offline

Administração local do cluster:

```bash
runuser -u postgres -- psql -h /var/run/postgresql -U postgres -d postgres -X -v ON_ERROR_STOP=1
```

No prompt psql, executar um comando por vez:

```text
CREATE ROLE canca_lab_admin LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE canca_lab_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\password canca_lab_admin
\password canca_lab_reader
CREATE DATABASE canca_p01_lab_r1 OWNER canca_lab_admin TEMPLATE template0;
\q
```

As duas senhas são definidas pelos prompts ocultos, não como literais SQL.
Roles/base já existentes: não excluir ou resetar; identificar antes de seguir.
No terminal do repo/venv, configurar conexão e digitar senha do admin sem exibi-la:

```bash
export PGHOST=127.0.0.1
export PGPORT=5432
export PGDATABASE=canca_p01_lab_r1
export PGUSER=canca_lab_admin
read -r -s -p 'Senha canca_lab_admin: ' P01_LAB_PASSWORD
export PGPASSWORD="$P01_LAB_PASSWORD"
unset P01_LAB_PASSWORD
python persistence/P01_PostgreSQL.py migrate
```

Esperado: migrated/migration 4. Segundo migrate retorna already_migrated.
Esta conta é owner somente da base LAB e serve para preparar os dados; isso não
qualifica separação completa de roles de deployment. Reader será testado abaixo;
indexer/lifecycle/assets/analyst e TLS permanecem gates separados do servidor.

Criar fontes sintéticas em diretório novo; o helper não acessa PostgreSQL:

```bash
python docs/validation/POSTGRESQL_LAB_FIXTURE_R1_v0.6.5.py --lab-root /var/lib/canca/postgres-lab
```

Copiar fixture_directory do JSON para P01_LAB_RUN (substituir o sufixo do exemplo):

```bash
export P01_LAB_RUN='/var/lib/canca/postgres-lab/P01-PG-R1-SUFIXO_REAL'
export P01_STORE_DIR="$P01_LAB_RUN/server-store"
cat "$P01_LAB_RUN/fixture-summary.json"
```

Para cada import_dir mostrado no summary, definir P01_IMPORT_DIR e executar as
três operações, primeiro a positive e depois negative:

```bash
export P01_IMPORT_DIR='COLE_AQUI_O_IMPORT_DIR_DO_SUMMARY'
python persistence/P01_PostgreSQL.py index-import --store-dir "$P01_STORE_DIR" --import-dir "$P01_IMPORT_DIR"
python persistence/P01_Asset_Registry.py project-import --store-dir "$P01_STORE_DIR" --import-dir "$P01_IMPORT_DIR"
python persistence/P01_Findings.py project-import --store-dir "$P01_STORE_DIR" --import-dir "$P01_IMPORT_DIR"
```

Repetir as três operações para cada import: already_indexed/already_projected,
IDs e contagens preservados. Sem AUTH/FULL/POST ou modificações no store ativo.

## 6. Consulta consolidada e reader

```bash
python persistence/P01_Assessment_Report.py show-assessment --assessment-id P01-PG-LAB-R1 --limit 1
```

Esperado no resumo: 2 imports/2 análises, 1 CAS, 2 observações, 4 avaliações,
2 finding + 2 no_finding, 2 ocorrências Open; state registered/revision 0.
has_more true. Copiar next_cursor e report_scope_sha256 para as páginas seguintes
conforme [guia](ASSESSMENT_REPORT_v0.6.5.md). Não há auto-close de findings positivos.

Como admin da base, aplicar grants do [guia](ASSESSMENT_REPORT_v0.6.5.md) trocando
canca_reader por canca_lab_reader. Via psql com conexão atual:

```bash
psql -X -v ON_ERROR_STOP=1
```

```sql
GRANT USAGE ON SCHEMA canca TO canca_lab_reader;
GRANT SELECT ON canca.schema_migrations, canca.assessments, canca.imports,
    canca.artifacts, canca.assets, canca.asset_imports, canca.asset_observations,
    canca.finding_analyses, canca.finding_evaluations, canca.findings TO canca_lab_reader;
```

Sair com \q. Trocar a conexão para reader e digitar sua senha pelo mesmo read oculto:

```bash
export PGUSER=canca_lab_reader
read -r -s -p 'Senha canca_lab_reader: ' P01_LAB_PASSWORD
export PGPASSWORD="$P01_LAB_PASSWORD"
unset P01_LAB_PASSWORD
python persistence/P01_Assessment_Report.py show-assessment --assessment-id P01-PG-LAB-R1 --limit 100
psql -X -v ON_ERROR_STOP=1 -c "UPDATE canca.findings SET status='Open';"
unset PGPASSWORD
```

Leitura passa e UPDATE falha por permission denied. Enviar resumo JSON, replay e
negação do reader, sem senhas. Base/store ficam preservados para backup/restore.
Não executar testes CI opt-in no LAB: suas classes recriam/destroem schema.

Se o PostgreSQL não for necessário enquanto o LAB está ocioso, parar manualmente
com systemctl stop postgresql. Sem enable, sem exclusão de fixture/cluster.

## Referências e limites

Instalação nativa: [PostgreSQL Red Hat/Rocky](https://www.postgresql.org/download/linux/redhat/).
Auth e ordem de regras: [pg_hba.conf 16](https://www.postgresql.org/docs/16/auth-pg-hba-conf.html).
Parâmetros: [recursos 16](https://www.postgresql.org/docs/16/runtime-config-resource.html).
Escolhas de memória/loopback/base são do roteiro Cancã para este LAB, não valores
prescritos pela documentação PostgreSQL. R1 básico não comprova backup/restore,
TLS remoto, alta disponibilidade ou produção. Esses gates terão evidência própria.
