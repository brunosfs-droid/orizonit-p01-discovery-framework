# Cancã — novo gate de download Web, R1 v0.6.13

**Código CI qualificado; CANDIDATE para o novo gate manual.** Web/API/restore/lifecycle/exportação CLI
anteriores continuam aprovados. Não repetir os testes antigos.
Este roteiro instala onze fontes da revisão `9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871`
em diretório novo, sem alterar os pacotes anteriores. Reutiliza somente a venv e
a persistência aprovadas. O launcher usa SELECT na base `canca_p01_restore_r1`,
sem escritores concorrentes, e remove sua conta/listener ao sair.

O teste novo é: consultar uma página, baixar o relatório **completo**, verificar
os quatro arquivos/hashes/contagens e encerrar com as 14 tabelas preservadas.
Não há restore, migração, coleta, instalação de serviço ou abertura de firewall.

## 1. Preparar o pacote no Windows

Na primeira janela PowerShell, em `C:\GitHub\canca`:

```powershell
$P01WebExportRelease = '9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871'
git fetch origin $P01WebExportRelease
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git fetch falhou.' }
$P01WebExportSources = @(
    'server/P01_Operator_Auth.py',
    'server/P01_Operator_API.py',
    'server/P01_Operator_Web.py',
    'server/P01_Operator_Export.py',
    'server/web/index.html',
    'server/web/operator.css',
    'server/web/operator.js',
    'persistence/P01_Report_Export.py',
    'docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py',
    'docs/validation/LOCAL_OPERATOR_WEB_EXPORT_LAB_R1_v0.6.13.py',
    'docs/validation/VERIFY_OPERATOR_WEB_EXPORT_v0.6.13.py'
)
git archive --format=tar --output "$env:TEMP\canca-operator-web-export-v0.6.13.tar" $P01WebExportRelease @P01WebExportSources
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git archive falhou.' }
Get-FileHash "$env:TEMP\canca-operator-web-export-v0.6.13.tar" -Algorithm SHA256
scp "$env:TEMP\canca-operator-web-export-v0.6.13.tar" root@192.168.100.50:/root/p01/
if ($LASTEXITCODE -ne 0) { throw 'PARAR: envio falhou.' }
```

## 2. Instalar somente as fontes novas no Rocky

Na janela SSH como root:

```bash
sha256sum /root/p01/canca-operator-web-export-v0.6.13.tar
```

Compare com o hash exibido no Windows. Depois da igualdade:

```bash
python3 - <<'PY'
import hashlib
from pathlib import Path
import tarfile

package = Path('/root/p01/canca-operator-web-export-v0.6.13.tar')
target = Path('/root/p01/canca-operator-web-export-lab-v0.6.13')
expected = {
    "server/P01_Operator_Auth.py": "c93b7764752df82d674f9be94c76520a7b4c562891099186c547175604eb70b3",
    "server/P01_Operator_API.py": "39da6f347505cec52e00cefb003e0031a69dfc3ffe7da7fc84db655eb5661e27",
    "server/P01_Operator_Web.py": "d74d19a8054e343142624397b5bb27f2b7f6b4630ee3eba8782c812cef461c8b",
    "server/P01_Operator_Export.py": "18711fbd3574f6de87403eb6704f10d9de25e8bd29bed6fa2f35f19520264f8c",
    "server/web/index.html": "7cb89ff3fa7f68578f2b89cb5dfc1b135d1ede967bcca84e0b0007946a8753de",
    "server/web/operator.css": "631b540cda9f6b7430a67e945f238b8438d29b522f41251f2e510274a446c297",
    "server/web/operator.js": "d0b3ac1360961745d839d1a487cabb0045eaeeb241010784ebb058eb03810d61",
    "persistence/P01_Report_Export.py": "eed3283655ddc8916407ddc7f0cb5b80c726e4145b4605c4fa4fe9cd10891aad",
    "docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py": "9e070d0177e773a714a955acee82f512dfa67397e59393e6dac7c726c00a3223",
    "docs/validation/LOCAL_OPERATOR_WEB_EXPORT_LAB_R1_v0.6.13.py": "20fcf5c2db778809ccab8f46238c12b9d15a889f624f91c3c0a07810bf5a3e94",
    "docs/validation/VERIFY_OPERATOR_WEB_EXPORT_v0.6.13.py": "f05a21d5f51d81ae6bfb7f85701762d42eb4c47f6130582c0f9e92e5c5e0d908"
}
def require(ok, message):
    if not ok:
        raise SystemExit('PARAR: ' + message)

require(package.is_file() and 0 < package.stat().st_size <= 2*1024**2, 'pacote invalido')
require(target.parent.is_dir() and target.parent.absolute() == target.parent.resolve(), 'raiz invalida')
require(not target.exists() and not target.is_symlink(), 'preservar diretorio existente')
with tarfile.open(package, 'r:') as archive:
    members = archive.getmembers()
    allowed_dirs = {'server', 'server/web', 'persistence', 'docs', 'docs/validation'}
    require(len(members) <= len(expected)+len(allowed_dirs), 'inventario excedido')
    require(len({m.name for m in members}) == len(members), 'entrada duplicada')
    files = [m for m in members if m.isfile()]
    require({m.name for m in files} == set(expected), 'inventario diferente')
    require(all(m.isfile() or m.isdir() and m.name.rstrip('/') in allowed_dirs for m in members), 'tipo invalido')
    payloads = {}
    for member in files:
        require(0 < member.size <= 65536, 'fonte excedida')
        raw = archive.extractfile(member).read(65537).replace(b'\r\n', b'\n')
        require(hashlib.sha256(raw).hexdigest() == expected[member.name], 'fonte diferente da qualificada')
        payloads[member.name] = raw
target.mkdir(mode=0o700)
for name, raw in payloads.items():
    destination = target/name
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with destination.open('xb') as output:
        output.write(raw)
    destination.chmod(0o600)
print('OPERATOR WEB EXPORT PACKAGE OK — 11 fontes, persistencia aprovada preservada')
PY
```

Se houver erro, preservar os arquivos. Não remover diretórios para contornar.

## 3. Iniciar o servidor temporário no Rocky

Depois de PACKAGE OK. O primeiro prompt é a senha PostgreSQL já utilizada.
Os dois seguintes criam uma senha sintética nova de 15–256 caracteres para
`reader-export`; use-a somente neste teste, sem reutilizar credenciais de alvos.

```bash
export PGHOST=127.0.0.1
export PGPORT=5432
export PGDATABASE=canca_p01_restore_r1
export PGUSER=canca_lab_admin
unset CANCA_TEST_POSTGRES
read -r -s -p 'Senha PostgreSQL canca_lab_admin: ' P01_WEB_EXPORT_DB_PASSWORD
echo
export PGPASSWORD="$P01_WEB_EXPORT_DB_PASSWORD"
unset P01_WEB_EXPORT_DB_PASSWORD
if PYTHONPATH=/root/p01/canca-postgres-lab-v0.6.5/persistence /root/p01/canca-postgres-lab-v0.6.5/.venv/bin/python /root/p01/canca-operator-web-export-lab-v0.6.13/docs/validation/LOCAL_OPERATOR_WEB_EXPORT_LAB_R1_v0.6.13.py; then
    echo 'INVARIANTES WEB EXPORT VALIDADAS NESTA SESSAO: true'
else
    echo 'PARAR: verificacao Web export LAB falhou'
fi
unset PGPASSWORD
```

Deixe essa janela aberta em `OPERATOR WEB EXPORT LAB READY`, versão 0.6.13.
Se a porta estiver ocupada, parar e preservar o processo existente.

## 4. Baixar pela Web no Windows

Em outra janela PowerShell, abra o mesmo túnel:

```powershell
ssh -o ExitOnForwardFailure=yes -N -L 127.0.0.1:8878:127.0.0.1:8878 root@192.168.100.50
```

Deixe aberto. No Edge/Chrome, abra <http://127.0.0.1:8878/>.
HTTP fica em loopback; Windows–Rocky usa SSH. Não é qualificação de HTTPS remoto.

1. Entre como `reader-export` com a senha sintética. Escolha **Agora não**
   se o navegador oferecer guardar a senha temporária.
2. Consulte `P01-PG-LAB-R1` com **1 avaliação por página**.
   O resumo mostra 1 asset, 4 avaliações e 2 findings históricos.
3. Na primeira página, clique **Baixar relatório completo (ZIP)**.
   Esperado: `canca-P01-PG-LAB-R1-report.zip` e mensagem de download preparado.
   Não precisa percorrer páginas, testar OTHER ou repetir logout/reload.

## 5. Verificar o arquivo no Windows

Volte à **primeira janela PowerShell**, a usada para preparar o pacote.
O comando lê o verificador da revisão fixada e executa somente verificação local
do ZIP; não precisa atualizar o checkout nem conectar ao banco.

```powershell
$P01WebExportRelease = '9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871'
$P01WebExportZip = "$env:USERPROFILE\Downloads\canca-P01-PG-LAB-R1-report.zip"
if (-not (Test-Path -LiteralPath $P01WebExportZip -PathType Leaf)) { throw 'PARAR: informe o caminho real do ZIP baixado.' }
$P01WebExportVerifier = git show "${P01WebExportRelease}:docs/validation/VERIFY_OPERATOR_WEB_EXPORT_v0.6.13.py"
if ($LASTEXITCODE -ne 0) { throw 'PARAR: verificador fixado ausente.' }
$P01WebExportVerifier | python - --archive $P01WebExportZip --assessment-id P01-PG-LAB-R1 --evaluation-count 4 --finding-count 2
if ($LASTEXITCODE -ne 0) { throw 'PARAR: verificacao do arquivo falhou.' }
```

Se o navegador salvou em outro lugar ou acrescentou `(1)` ao nome, ajuste somente
`$P01WebExportZip` para o arquivo realmente baixado.
Esperado: **OPERATOR WEB EXPORT FILE PASS**, `files_verified=4`,
`evaluations=4`, `historical_findings=2` e cerca terminal verificada.
Isso confirma que o download contém todas as avaliações, embora a tela mostre uma.

## 6. Encerrar e enviar evidência do novo gate

Clique **Sair** apenas para encerrar a sessão. Pressione **Ctrl+C no Rocky**.
Esperado: **OPERATOR WEB EXPORT LAB STOP PASS**, `web_version=0.6.13`,
`tables_compared=14`, `database_mutated=false`, `store_accessed=false`,
servidor parado/contas removidas e o marcador de invariantes `true`.
O bloco limpa PGPASSWORD ao terminar. Encerre o túnel com Ctrl+C.

Envie somente as evidências novas: PACKAGE OK, tela com download preparado,
verificador FILE PASS e STOP PASS. Não enviar senha, token ou arquivo de contas.
FILE PASS verifica o arquivo; STOP PASS verifica o banco/cleanup. Nenhum dos dois
substitui qualificação de produção. Se falhar, envie a etapa e a mensagem visível,
preservando os arquivos e sem repetir os R1 antigos.

[Guia e limites](OPERATOR_WEB_EXPORT_v0.6.13.md) ·
[ADR 0025](ADR_0025_Operator_Web_Report_Export_v0.6.13.md).

[Qualificação CI](validation/OPERATOR_WEB_EXPORT_CI_v0.6.13.md).
