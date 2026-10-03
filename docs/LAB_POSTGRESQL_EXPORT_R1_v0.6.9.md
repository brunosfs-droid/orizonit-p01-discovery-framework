# P01 — teste de exportação do relatório R1 v0.6.9

Lifecycle/paginação R1 aprovado. Exportador integrado pelo PR #105 e corrigido pelo
PR #106, merge d1b32cf6d6185e87fc4a08abb57654c29d8e8c4b, tree idêntica ao head
qualificado 361ff2b78e47ecc23d57d13f7b86a497ab184490. **Não repetir restore ou exercise.** Este teste
consulta a base recuperada e escreve somente novos arquivos em uma raiz de exportação.
Executar sem outros escritores na fixture. Não usa AUTH/FULL/POST, migrations ou testes destrutivos.

## 1. Enviar somente o exportador novo

Windows PowerShell, no repositório C:\GitHub\orizonit-p01-discovery-framework:

```powershell
git fetch origin
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git fetch falhou.' }
$P01ExportRelease = 'd1b32cf6d6185e87fc4a08abb57654c29d8e8c4b'
git archive --format=tar --output "$env:TEMP\canca-export-v0.6.9.tar" $P01ExportRelease persistence/P01_Report_Export.py
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git archive falhou.' }
Get-FileHash "$env:TEMP\canca-export-v0.6.9.tar" -Algorithm SHA256
if (-not $?) { throw 'PARAR: hash do TAR indisponivel.' }
scp "$env:TEMP\canca-export-v0.6.9.tar" root@192.168.100.50:/root/p01/
if ($LASTEXITCODE -ne 0) { throw 'PARAR: envio falhou.' }
```

Pare se algum comando falhar. Rocky: conferir SHA do tar contra Windows antes
do próximo bloco. Ele aceita o único arquivo regular esperado e a entrada opcional
da pasta `persistence/` criada pelo Git. Não extrai a pasta. Valida os hashes do
exportador desta revisão (LF ou CRLF) e do engine original; não
sobrescreve cópia diferente nem atualiza os módulos já usados na recuperação.

```bash
sha256sum /root/p01/canca-export-v0.6.9.tar
cd /root/p01/canca-postgres-lab-v0.6.5
source .venv/bin/activate
P01_EXPORT_READY=false
if python - <<'PY'
import hashlib
from pathlib import Path
import tarfile

root = Path('/root/p01/canca-postgres-lab-v0.6.5')
assert root.absolute() == root.resolve(), 'PARAR: deployment com alias'
engine = root/'persistence/P01_Findings.py'
assert hashlib.sha256(engine.read_bytes()).hexdigest() == '57c0b7834095d00512e6046bd884c03556f46738e97d7fdb4dcb9847efcc2365', 'PARAR: engine original diferente'
package = Path('/root/p01/canca-export-v0.6.9.tar')
assert package.is_file() and 0 < package.stat().st_size <= 2 * 1024**2, 'PARAR: tamanho do tar diferente'
with tarfile.open(package, 'r:') as archive:
    members = archive.getmembers()
    files = [m for m in members if m.isfile() and m.name == 'persistence/P01_Report_Export.py']
    directories = [m for m in members if m.isdir() and m.name in ('persistence', 'persistence/')]
    assert len(files) == 1 and len(directories) <= 1 and len(members) == len(files) + len(directories), 'PARAR: inventario do tar diferente'
    member = files[0]
    assert 0 < member.size <= 1024**2, 'PARAR: tamanho do exportador diferente'
    raw = archive.extractfile(member).read()
assert len(raw) == member.size
assert hashlib.sha256(raw).hexdigest() in {
    'd2ec90a2624d9c374a53a76e9307417eddf8c89b77d9c3dff06983b319d07bd8',
    'd409898b63be0477d08319a3a13f090d79bf05cdcbdc3ff3699e49128cf1e830',
}, 'PARAR: exportador diferente da revisao qualificada'
assert b"VERSION = '0.6.9'" in raw
target = root/member.name
assert target.parent.absolute() == target.parent.resolve()
if target.exists() or target.is_symlink():
    assert target.is_file() and target.absolute() == target.resolve() and target.read_bytes() == raw, 'PARAR: exportador existente diferente'
else:
    with target.open('xb') as output:
        output.write(raw)
assert hashlib.sha256(engine.read_bytes()).hexdigest() == '57c0b7834095d00512e6046bd884c03556f46738e97d7fdb4dcb9847efcc2365'
print('EXPORTADOR OK — engine original preservado')
PY
then
  P01_EXPORT_READY=true
else
  echo 'PARAR: instalacao nao validada; nao exportar.'
fi
echo "Instalacao validada nesta sessao: $P01_EXPORT_READY"
```

## 2. Exportar duas vezes e verificar os arquivos

Copie o bloco inteiro na **mesma sessão Rocky**. A senha não aparece na tela.
A raiz /var/lib/canca/report-exports fica fora do store; não substituir por um
caminho de evidências. Dois diretórios novos serão criados, páginas de 1 e de 100.

```bash
unset PGSERVICE PGHOSTADDR PGPASSWORD
unset P01_EXPORT_RESULT_ONE P01_EXPORT_RESULT_TWO
P01_EXPORT_OK=false
if [ "${P01_EXPORT_READY:-false}" = true ]; then
  export PGHOST=127.0.0.1
  export PGPORT=5432
  export PGUSER=canca_lab_admin
  export PGDATABASE=canca_p01_restore_r1
  mkdir -p /var/lib/canca/report-exports
  chmod 700 /var/lib/canca/report-exports
  read -r -s -p 'Senha canca_lab_admin: ' P01_EXPORT_PASSWORD
  echo
  export PGPASSWORD="$P01_EXPORT_PASSWORD"
  unset P01_EXPORT_PASSWORD
  if P01_EXPORT_RESULT_ONE="$(python persistence/P01_Report_Export.py --assessment-id P01-PG-LAB-R1 --output-root /var/lib/canca/report-exports --page-size 1)"; then
    echo "$P01_EXPORT_RESULT_ONE"
    export P01_EXPORT_RESULT_ONE
    if P01_EXPORT_RESULT_TWO="$(python persistence/P01_Report_Export.py --assessment-id P01-PG-LAB-R1 --output-root /var/lib/canca/report-exports --page-size 100)"; then
      echo "$P01_EXPORT_RESULT_TWO"
      export P01_EXPORT_RESULT_TWO
      if python - <<'PY'
import hashlib
import json
import os
from pathlib import Path

documents = []
directories = []
for key in ('P01_EXPORT_RESULT_ONE', 'P01_EXPORT_RESULT_TWO'):
    result = json.loads(os.environ[key])
    assert result['status'] == 'exported' and result['export_version'] == '0.6.9'
    assert result['database_mutated'] is False and result['source_bytes_revalidated'] is False
    run = Path(result['export_dir'])
    assert run == run.resolve() and run.parent == Path('/var/lib/canca/report-exports')
    assert run.stat().st_mode & 0o777 == 0o700
    assert {p.name for p in run.iterdir()} == {'report.json', 'report.md', 'manifest.json', 'manifest.json.sha256'}
    raw = (run/'manifest.json').read_bytes()
    manifest_sha = hashlib.sha256(raw).hexdigest()
    assert manifest_sha == result['manifest_sha256']
    assert (run/'manifest.json.sha256').read_text() == manifest_sha + '  manifest.json\n'
    manifest = json.loads(raw)
    assert {f['name'] for f in manifest['files']} == {'report.json', 'report.md'}
    for entry in manifest['files']:
        payload = (run/entry['name']).read_bytes()
        assert len(payload) == entry['size_bytes'] and hashlib.sha256(payload).hexdigest() == entry['sha256']
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in run.iterdir())
    doc = json.loads((run/'report.json').read_bytes())
    assert doc['assessment_id'] == 'P01-PG-LAB-R1'
    assert doc['lifecycle'] == {'state': 'completed', 'revision': 4}
    assert doc['identity']['central_asset_count'] == 1 and doc['identity']['observation_count'] == 2
    assert doc['coverage']['evaluation_count'] == 4 and len(doc['evaluations']) == 4
    assert doc['coverage']['outcomes'] == {'finding': 2, 'no_finding': 2, 'insufficient_evidence': 0, 'not_applicable': 0, 'not_supported': 0}
    assert doc['recorded_finding_occurrences'] == 2
    assert all(r['finding_status'] == 'Open' for r in doc['evaluations'] if r['finding_id'])
    assert doc['export_consistency']['terminal_empty_page_verified'] is True
    assert doc['report_scope_sha256'] == result['report_scope_sha256'] == manifest['report_scope_sha256']
    directories.append(str(run))
    documents.append(doc)
assert directories[0] != directories[1]
assert documents[0]['export_consistency']['data_pages'] == 4
assert documents[1]['export_consistency']['data_pages'] == 1
assert {k:v for k,v in documents[0].items() if k != 'export_consistency'} == {k:v for k,v in documents[1].items() if k != 'export_consistency'}
print('POSTGRESQL LAB EXPORT PASS — 4 avaliacoes, 2 findings Open, hashes/permissoes OK, dois diretorios distintos')
for directory in directories:
    print(directory)
PY
      then
        P01_EXPORT_OK=true
      else
        echo 'PARAR: arquivos/contagens nao validados; preservar as saidas para diagnostico.'
      fi
    else
      echo "$P01_EXPORT_RESULT_TWO"
      echo 'PARAR: segunda exportacao falhou.'
    fi
  else
    echo "$P01_EXPORT_RESULT_ONE"
    echo 'PARAR: primeira exportacao falhou.'
  fi
else
  echo 'PARAR: execute a instalacao validada da etapa 1 primeiro.'
fi
unset PGPASSWORD
echo "Exportacao validada nesta sessao: $P01_EXPORT_OK"
```

## Resultado a enviar

Enviar capturas de EXPORTADOR OK, dois JSONs `exported` e POSTGRESQL LAB EXPORT PASS
com `Exportacao validada nesta sessao: true`, sem credenciais. Conferir também a
leitura/apresentação do report.md pelo caminho real exibido; não publicar os arquivos
automaticamente. Pode enviar o Markdown/JSON sintético para revisar a apresentação.

Esta entrega não altera lifecycle/findings nem substitui seu aceite anterior.
Repetir exportação é uma nova observação: timestamps e hashes podem ser diferentes.
Somente a igualdade semântica, sob o mesmo escopo estável, é esperada nesse teste.
`report_scope_conflict` significa mudança concorrente; preserve a saída, interrompa
e informe o diagnóstico. Não migrar/reparar ou restaurar novamente para contornar.

## Diagnóstico das capturas 235251/235559/235634/235648

A instalação anterior rejeitou o inventário do TAR antes de gravar o exportador.
O Git inclui a entrada da pasta `persistence/`; o roteiro anterior exigia exatamente
uma entrada. As demais capturas mostram o bloco de exportação bloqueado por
`P01_EXPORT_READY=false`, sem JSON `exported` ou `POSTGRESQL LAB EXPORT PASS`.
Essas capturas não aprovam nem reprovam a consulta ao banco: o teste não chegou
à exportação. Lifecycle/paginação e recuperação continuam aprovados.

Refazer apenas o envio do exportador desta revisão, a instalação corrigida e a
etapa 2 na mesma sessão. Não apagar um exportador existente diferente para
contornar o bloqueio: preservar e informar. Não reutilizar o TAR anterior, que
contém o Markdown anterior à correção do PR #106.
