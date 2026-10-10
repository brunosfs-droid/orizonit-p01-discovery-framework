# Cancã — recuperação PostgreSQL R1 no Rocky v0.6.7

**R1 básico já aprovado; não repetir instalação/import/reader.** [Aceite](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md). Esta etapa compara backup/restauração do par banco/store isolado; execução LAB pendente. O helper só lê banco/store e cria captura nova; os comandos de dump/restore são ações explícitas do operador. Nunca executar `tests/postgres_backup_restore_smoke.py` no LAB.

Preserve origem `canca_p01_lab_r1`, fixture `P01-PG-R1-06230404e329` e arquivos existentes do deployment v0.6.5. Destino: **nova base canca_p01_restore_r1**, owner canca_lab_admin, store copiado em diretório novo. Se destino já existir ou qualquer comando falhar, parar e enviar a saída; não usar DROP, --clean, --create ou initdb.

## 1. Entregar código v0.6.7 separado

No PowerShell do Windows, venv/repositório existentes:

```powershell
Set-Location C:\GitHub\canca
git pull origin main
$P01Commit = 'COLE_O_MERGE_SHA_V067_DO_RELATORIO_DE_VALIDACAO'
git archive --format=tar --output=C:\Canca\canca-postgres-lab-v0.6.7.tar $P01Commit
Get-FileHash C:\Canca\canca-postgres-lab-v0.6.7.tar -Algorithm SHA256
scp C:\Canca\canca-postgres-lab-v0.6.7.tar root@192.168.100.50:/root/p01/
```

No Rocky como root, conferir SHA igual ao Windows; novo diretório não deve existir:

```bash
sha256sum /root/p01/canca-postgres-lab-v0.6.7.tar
mkdir /root/p01/canca-postgres-lab-v0.6.7
tar -xf /root/p01/canca-postgres-lab-v0.6.7.tar -C /root/p01/canca-postgres-lab-v0.6.7
python3 - <<'PYHELPER'
from pathlib import Path
source = Path('/root/p01/canca-postgres-lab-v0.6.7/docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py')
target = Path('/root/p01/canca-postgres-lab-v0.6.5/docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py')
with target.open('xb') as output:
    output.write(source.read_bytes())
print('HELPER COPIED — existing deployment files preserved')
PYHELPER
cd /root/p01/canca-postgres-lab-v0.6.5
source .venv/bin/activate
sha256sum persistence/P01_Findings.py
psql --version
pg_dump --version
pg_restore --version
```

A cópia adiciona somente o helper novo ao deployment original e recusa sobrescrever um helper existente. Se o arquivo já existir, parar e enviar a saída. As CLIs e módulos de projeção continuam exatamente os que produziram os dados aprovados; não substitua os arquivos de persistence do v0.6.5.

SHA esperado de persistence/P01_Findings.py no deployment original: **57c0b7834095d00512e6046bd884c03556f46738e97d7fdb4dcb9847efcc2365**, apresentado no relatório do LAB. As capturas correspondem a CRLF; converter esse código para LF muda o hash do engine. Se o SHA divergir, não editar o banco/sidecars para forçar igualdade: enviar a saída antes de seguir. CI exercita o helper com os módulos originais de sua própria fixture, em LF; isso não autoriza recalcular o histórico do LAB.

As três ferramentas devem ser 16.15/major 16. Não migre ou gere outra fixture: utilize os dados já aprovados. Mantenha a API existente com seu store atual; ela não escreve nesta base/fixture. Não execute import/lifecycle/assets/findings na origem durante toda esta etapa; aguarde operações pendentes terminarem. Não há snapshot distribuído com escritores ativos.

## 2. Capturar origem e copiar o par banco/store

Na mesma janela Rocky, definir ambiente explicitamente e digitar senha admin oculta:

```bash
unset PGSERVICE PGHOSTADDR
export PGHOST=127.0.0.1
export PGPORT=5432
export PGUSER=canca_lab_admin
export PGDATABASE=canca_p01_lab_r1
read -r -s -p 'Senha canca_lab_admin: ' P01_LAB_PASSWORD
export PGPASSWORD="$P01_LAB_PASSWORD"
unset P01_LAB_PASSWORD
export P01_LAB_RUN=/var/lib/canca/postgres-lab/P01-PG-R1-06230404e329
export P01_SOURCE_STORE="$P01_LAB_RUN/server-store"
install -d -m 700 /var/lib/canca/postgres-recovery
export P01_RECOVERY_DIR="$(mktemp -d /var/lib/canca/postgres-recovery/P01-PG-RECOVERY-XXXXXXXX)"
python docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py capture \
  --store-dir "$P01_SOURCE_STORE" --expected-database canca_p01_lab_r1 \
  --evidence-root "$P01_RECOVERY_DIR/source-proof"
```

Esperado POSTGRESQL LAB SNAPSHOT READY, tables_compared=14, store_file_count=20, source_bytes_revalidated=true e database_mutated/store_mutated=false. Copie o caminho exato de snapshot_path para a variável abaixo (não é senha):

```bash
export P01_REFERENCE='COLE_O_CAMINHO_SNAPSHOT_PATH_AQUI'
pg_dump --host=127.0.0.1 --port=5432 --username=canca_lab_admin \
  --dbname=canca_p01_lab_r1 --format=custom --file="$P01_RECOVERY_DIR/database.dump"
sha256sum "$P01_RECOVERY_DIR/database.dump" > "$P01_RECOVERY_DIR/database.dump.sha256"
pg_restore --list "$P01_RECOVERY_DIR/database.dump" > "$P01_RECOVERY_DIR/restore-list.txt"
cp -a -- "$P01_SOURCE_STORE" "$P01_RECOVERY_DIR/restored-store"
export P01_RESTORED_STORE="$P01_RECOVERY_DIR/restored-store"
python docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py verify \
  --store-dir "$P01_RESTORED_STORE" --expected-database canca_p01_lab_r1 \
  --reference "$P01_REFERENCE"
```

Esse primeiro PASS compara **store copiado com base de origem** e detecta mudanças durante a cópia; ainda não é aceite da restauração. Verifique exit 0 após pg_dump, pg_restore --list, cp e helper antes de prosseguir. O dump não inclui o store; os dois devem permanecer juntos. Não editar receipts/sidecars nem reutilizar o diretório para outra coleta.

## 3. Restaurar em base nova

Admin do cluster via socket local peer, sem mudar HBA/roles:

```bash
runuser -u postgres -- psql -h /var/run/postgresql -U postgres -d postgres -X \
  -v ON_ERROR_STOP=1 -c "CREATE DATABASE canca_p01_restore_r1 OWNER canca_lab_admin TEMPLATE template0;"
pg_restore --host=127.0.0.1 --port=5432 --username=canca_lab_admin \
  --dbname=canca_p01_restore_r1 --single-transaction --exit-on-error \
  --no-owner --no-privileges "$P01_RECOVERY_DIR/database.dump"
export PGDATABASE=canca_p01_restore_r1
python docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py verify \
  --store-dir "$P01_RESTORED_STORE" --expected-database canca_p01_restore_r1 \
  --reference "$P01_REFERENCE"
python persistence/P01_Assessment_Report.py show-assessment --assessment-id P01-PG-LAB-R1 --limit 100
```

Esperado **POSTGRESQL LAB RECOVERY PASS em expected_database=canca_p01_restore_r1**, 14 tabelas/20 arquivos, revalidação=true e sem mutações do helper. Relatório: mesmo registered/revision 0, 1 CAS/2 observações, 4 avaliações, 2 findings Open + 2 no_finding. A restauração não muda o significado do lifecycle.

--no-owner faz o usuário do restore possuir os objetos; --no-privileges omite grants. As permissões do reader aprovadas na origem **não são restauradas** nem qualificadas por este gate. Mantenha as contas existentes; roles de escrita separados e reprovisionamento de grants terão gate próprio.

## 4. Replay no destino e nova comparação

Somente depois do PASS na base destino, executar replay explicitamente nela. Usa IDs da fixture original, mas caminhos de evidência restaurados:

```bash
python - <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()/'persistence'))
import P01_PostgreSQL as pg
import P01_Asset_Registry as assets
import P01_Findings as findings
assert os.environ['PGDATABASE'] == 'canca_p01_restore_r1'
summary = json.loads((Path(os.environ['P01_LAB_RUN'])/'fixture-summary.json').read_text())
store = Path(os.environ['P01_RESTORED_STORE'])
with pg.open_connection() as conn:
    assert conn.execute('SELECT current_database()').fetchone()[0] == 'canca_p01_restore_r1'
    for item in summary['imports']:
        directory = store/'assessments'/summary['assessment_id']/'imports'/item['bundle_id']
        for name, result, expected in (
            ('index', pg.index_import(conn, pg.prepare_import(store, directory)), 'already_indexed'),
            ('assets', assets.project_import(conn, assets.prepare_assets(store, directory)), 'already_projected'),
            ('findings', findings.project_import(conn, findings.prepare_findings(store, directory)), 'already_projected')):
            print(json.dumps(dict(stage=name, **result)))
            assert result['status'] == expected
PY
python docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py verify \
  --store-dir "$P01_RESTORED_STORE" --expected-database canca_p01_restore_r1 \
  --reference "$P01_REFERENCE"
sha256sum "$P01_RECOVERY_DIR/database.dump"
unset PGPASSWORD
```

Enviar os resumos de capture, verify no destino antes/depois do replay, relatório e SHA do dump; podem ser capturas como no R1 básico. Não enviar dump/store, senhas ou credenciais. Conservar banco/store de origem e de destino e o diretório de verificação. Nenhuma remoção automática ou execução live de coleta nesta etapa.

## Limites

Helper exclusivo da fixture R1 (2 imports completos/1 assessment), limites de linhas/arquivos e código de projeção original. Não é validador de bancos gerais. Um mismatch é recusa de aceite, não comando de reparo. Os tempos/hash de CI não estabelecem RTO/RPO para o Rocky; TLS remoto, HA/PITR/retention, agendamento, roles/grants e snapshots com concorrência não são qualificados.

Referências: [pg_dump 16](https://www.postgresql.org/docs/16/app-pgdump.html), [pg_restore 16](https://www.postgresql.org/docs/16/app-pgrestore.html), [ADR 0018](ADR_0018_LAB_Recovery_Check_v0.6.7.md).

## Atualização após recuperação R1

Recuperação sintética no Rocky/PostgreSQL 16.15 **LAB VALIDATED** por sete capturas: restore
em canca_p01_restore_r1, comparação de 14 tabelas/20 arquivos, revalidação de fontes
e replay preservado. Esta observação substitui a pendência anterior de restore operacional
R1; não qualifica produção, roles/TLS ou toda a Product Alpha.
[Aceite e limites](validation/POSTGRESQL_P01LAB_RECOVERY_R1_v0.6.7.md) ·
[Próximo gate lifecycle/paginação](LAB_POSTGRESQL_LIFECYCLE_R1_v0.6.8.md).
