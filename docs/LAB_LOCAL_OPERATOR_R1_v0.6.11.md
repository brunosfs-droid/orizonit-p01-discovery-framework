# Cancã — login local do servidor, R1 curto v0.6.11

**CANDIDATE; aceite de host pendente.** Collector portable continua sem login.
Este teste valida somente o backend de operadores do servidor, antes das telas
Web. Integração AD é opcional/futura. Não instalar serviços nem abrir firewall.

Usa a base recuperada `canca_p01_restore_r1`, sem escritores concorrentes,
somente SELECTs. Reutiliza o Python/driver e os módulos de persistência do
deployment aprovado, preservando os bytes de SQL/checksums/engine do Windows.
Três arquivos novos ficam em diretório separado. O helper cria e remove contas
sintéticas privadas em área temporária; não pede senha de operador nem guarda
tokens no output. PostgreSQL e store aprovados são preservados.

## 1. Pacote no Windows

PowerShell no repositório `C:\GitHub\orizonit-p01-discovery-framework`:

```powershell
git fetch origin
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git fetch falhou.' }
$P01OperatorRelease = '84437c8e6f0e6aa6976279ae26e1866cd123371a'
git archive --format=tar --output "$env:TEMP\canca-operator-v0.6.11.tar" $P01OperatorRelease server/P01_Operator_Auth.py server/P01_Operator_API.py docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git archive falhou.' }
Get-FileHash "$env:TEMP\canca-operator-v0.6.11.tar" -Algorithm SHA256
scp "$env:TEMP\canca-operator-v0.6.11.tar" root@192.168.100.50:/root/p01/
if ($LASTEXITCODE -ne 0) { throw 'PARAR: envio falhou.' }
```

## 2. Extrair somente os três arquivos qualificados

Rocky, mesma janela SSH como root. Primeiro:

```bash
sha256sum /root/p01/canca-operator-v0.6.11.tar
```

Compare com o SHA256 exibido no Windows. Se diferente, parar e preservar o
arquivo. Somente após igualdade, executar o bloco abaixo. Ele verifica os três
hashes, permite apenas diretórios estruturais do Git, rejeita links/entradas
extras e cria um diretório novo. Não sobrescreve uma instalação existente.

```bash
python3 - <<'PY'
import hashlib
from pathlib import Path
import tarfile

package = Path('/root/p01/canca-operator-v0.6.11.tar')
target = Path('/root/p01/canca-operator-lab-v0.6.11')
expected = {
    'server/P01_Operator_Auth.py': 'c93b7764752df82d674f9be94c76520a7b4c562891099186c547175604eb70b3',
    'server/P01_Operator_API.py': '39da6f347505cec52e00cefb003e0031a69dfc3ffe7da7fc84db655eb5661e27',
    'docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py': '9e070d0177e773a714a955acee82f512dfa67397e59393e6dac7c726c00a3223',
}
assert target.parent.absolute() == target.parent.resolve()
assert not target.exists() and not target.is_symlink(), 'PARAR: preservar diretorio existente'
with tarfile.open(package, 'r:') as archive:
    members = archive.getmembers()
    assert len({m.name for m in members}) == len(members), 'PARAR: entrada duplicada'
    files = [m for m in members if m.isfile()]
    assert {m.name for m in files} == set(expected), 'PARAR: inventario diferente'
    assert all(m.isfile() or m.isdir() and m.name.rstrip('/') in {'server','docs','docs/validation'} for m in members)
    payloads = {}
    for member in files:
        assert 0 < member.size <= 65536
        raw = archive.extractfile(member).read(65537).replace(b'\r\n', b'\n')
        assert hashlib.sha256(raw).hexdigest() == expected[member.name], 'PARAR: fonte diferente da qualificada'
        payloads[member.name] = raw
target.mkdir(mode=0o700)
for name, raw in payloads.items():
    destination = target/name
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with destination.open('xb') as output:
        output.write(raw)
    destination.chmod(0o600)
print('OPERATOR PACKAGE OK — persistencia aprovada preservada')
PY
```

Esperado: `OPERATOR PACKAGE OK — persistencia aprovada preservada`. Se o bloco
falhar, parar; não executar o helper nem apagar o diretório para contornar o erro.

## 3. Executar a checagem

Na mesma janela, somente após PACKAGE OK. A conta `canca_lab_admin` já foi usada
no aceite dessa base; este teste não a promove a role de produção. Reader
SELECT-only foi testado separadamente em CI; qualificação própria de role/TLS no
host continua independente. Não alterar grants para contornar falhas.

```bash
export PGHOST=127.0.0.1
export PGPORT=5432
export PGDATABASE=canca_p01_restore_r1
export PGUSER=canca_lab_admin
unset CANCA_TEST_POSTGRES
read -r -s -p 'Senha PostgreSQL canca_lab_admin: ' P01_OPERATOR_LAB_PASSWORD
echo
export PGPASSWORD="$P01_OPERATOR_LAB_PASSWORD"
unset P01_OPERATOR_LAB_PASSWORD
if PYTHONPATH=/root/p01/canca-postgres-lab-v0.6.5/persistence /root/p01/canca-postgres-lab-v0.6.5/.venv/bin/python /root/p01/canca-operator-lab-v0.6.11/docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py; then
    echo 'OPERADORES VALIDADOS NESTA SESSAO: true'
else
    echo 'PARAR: validacao de operadores falhou'
fi
unset PGPASSWORD
```

Esperado: `LOCAL OPERATOR LAB PASS`, 4 avaliações, 2 findings históricos,
14 tabelas comparadas; login/negações/logout/páginas fenced `true`,
`database_mutated=false`, `store_accessed=false`, servidor temporário parado
e credenciais temporárias removidas. Depois `OPERADORES VALIDADOS NESTA SESSAO: true`.

Enviar somente as saídas PACKAGE OK e PASS, sem senha. Não enviar o arquivo de
contas ou tokens. Este R1 não qualifica acesso HTTPS entre hosts, AD, Web UI,
MFA, HA, produção ou o principal de coleta. Não repetir os gates aprovados.

[Guia e limites](../server/README.md) · [ADR 0023](ADR_0023_Local_Operator_API_v0.6.11.md).
