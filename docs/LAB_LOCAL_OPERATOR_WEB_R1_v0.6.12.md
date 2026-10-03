# Cancã — primeiras telas Web, R1 v0.6.12

**CANDIDATE; aceite de navegador pendente.** Executar quando Bruno retornar.
API v0.6.11 já aprovada; não repetir seu helper, restore, lifecycle ou exportação.
Collector portable continua sem login Cancã. AD permanece opcional/futuro.

Este roteiro mantém a base sintética `canca_p01_restore_r1` sem escritores
concorrentes. Instala oito fontes novas/qualificadas em diretório separado,
reutiliza a persistência/venv aprovadas e inicia servidor Web temporário em
127.0.0.1:8878. Uma conta sintética é criada em área privada temporária e removida
ao sair. O launcher compara as mesmas 14 tabelas antes/depois; não acessa o store.
Não instalar serviço, abrir firewall, mudar grants ou reutilizar senhas de alvos.

## 1. Pacote no Windows

PowerShell em `C:\GitHub\orizonit-p01-discovery-framework`:

```powershell
git fetch origin
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git fetch falhou.' }
$P01WebRelease = 'RELEASE_PENDING'
git archive --format=tar --output "$env:TEMP\canca-operator-web-v0.6.12.tar" $P01WebRelease server/P01_Operator_Auth.py server/P01_Operator_API.py server/P01_Operator_Web.py server/web/index.html server/web/operator.css server/web/operator.js docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py docs/validation/LOCAL_OPERATOR_WEB_LAB_R1_v0.6.12.py
if ($LASTEXITCODE -ne 0) { throw 'PARAR: git archive falhou.' }
Get-FileHash "$env:TEMP\canca-operator-web-v0.6.12.tar" -Algorithm SHA256
scp "$env:TEMP\canca-operator-web-v0.6.12.tar" root@192.168.100.50:/root/p01/
if ($LASTEXITCODE -ne 0) { throw 'PARAR: envio falhou.' }
```

## 2. Instalação isolada no Rocky

Na janela SSH atual como root:

```bash
sha256sum /root/p01/canca-operator-web-v0.6.12.tar
```

Compare com o hash no Windows. Somente após igualdade:

```bash
python3 - <<'PY'
import hashlib
from pathlib import Path
import tarfile

package = Path('/root/p01/canca-operator-web-v0.6.12.tar')
target = Path('/root/p01/canca-operator-web-lab-v0.6.12')
expected = {
    'server/P01_Operator_Auth.py': 'c93b7764752df82d674f9be94c76520a7b4c562891099186c547175604eb70b3',
    'server/P01_Operator_API.py': '39da6f347505cec52e00cefb003e0031a69dfc3ffe7da7fc84db655eb5661e27',
    'server/P01_Operator_Web.py': '5ee7b36c9a4986c53fafabdbd119384132bee24125890a5deaedb6d3b7c73063',
    'server/web/index.html': '349b019a4f2f15fc3a9234f3357b14ee199048e401e6e11c1b2b47e606f624b6',
    'server/web/operator.css': '733ce45760c92901f772dcb01f8236b968331cfe0463613d571b5751be762c17',
    'server/web/operator.js': 'ce4d67dc465b56ad29e96156ec4128435264bd13e625fc07375e0e81a7f54071',
    'docs/validation/LOCAL_OPERATOR_LAB_R1_v0.6.11.py': '9e070d0177e773a714a955acee82f512dfa67397e59393e6dac7c726c00a3223',
    'docs/validation/LOCAL_OPERATOR_WEB_LAB_R1_v0.6.12.py': '95ac603836e3d4da3d2b882488e3ba33aaf09de001afe54812a37be5fbdc8eec',
}
assert target.parent.absolute() == target.parent.resolve()
assert not target.exists() and not target.is_symlink(), 'PARAR: preservar diretorio existente'
with tarfile.open(package, 'r:') as archive:
    members = archive.getmembers()
    assert len({m.name for m in members}) == len(members), 'PARAR: entrada duplicada'
    files = [m for m in members if m.isfile()]
    assert {m.name for m in files} == set(expected), 'PARAR: inventario diferente'
    assert all(m.isfile() or m.isdir() and m.name.rstrip('/') in {'server','server/web','docs','docs/validation'} for m in members)
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
print('OPERATOR WEB PACKAGE OK — persistencia aprovada preservada')
PY
```

Se falhar, preservar os arquivos e parar; não remover destino para contornar.

## 3. Servidor temporário no Rocky

Somente depois de PACKAGE OK. A role LAB já usada permanece sem novos grants.
O primeiro prompt é da senha PostgreSQL; os dois seguintes criam uma senha
**sintética nova**, de 15–256 caracteres, que você usará apenas neste navegador.

```bash
export PGHOST=127.0.0.1
export PGPORT=5432
export PGDATABASE=canca_p01_restore_r1
export PGUSER=canca_lab_admin
unset CANCA_TEST_POSTGRES
read -r -s -p 'Senha PostgreSQL canca_lab_admin: ' P01_WEB_DB_PASSWORD
echo
export PGPASSWORD="$P01_WEB_DB_PASSWORD"
unset P01_WEB_DB_PASSWORD
if PYTHONPATH=/root/p01/canca-postgres-lab-v0.6.5/persistence /root/p01/canca-postgres-lab-v0.6.5/.venv/bin/python /root/p01/canca-operator-web-lab-v0.6.12/docs/validation/LOCAL_OPERATOR_WEB_LAB_R1_v0.6.12.py; then
    echo 'INVARIANTES WEB VALIDADAS NESTA SESSAO: true'
else
    echo 'PARAR: verificacao Web LAB falhou'
fi
unset PGPASSWORD
```

Deixe a janela aberta quando aparecer `OPERATOR WEB LAB READY`. Se a porta 8878
estiver ocupada ou houver erro, parar; não encerrar outro serviço para contornar.

## 4. Túnel e navegador no Windows

Em **outra janela PowerShell**, mantendo a janela Rocky aberta:

```powershell
ssh -o ExitOnForwardFailure=yes -N -L 127.0.0.1:8878:127.0.0.1:8878 root@192.168.100.50
```

Deixe o túnel aberto. No Edge/Chrome, abra <http://127.0.0.1:8878/>.
O acesso HTTP está restrito ao loopback em cada ponta; o trecho Windows–Rocky
usa SSH. Este teste não qualifica HTTPS remoto do produto.

1. Entre como `reader-web` com a senha sintética escolhida. Não capture a senha.
2. Consulte `P01-PG-LAB-R1`, com **1 avaliação por página**. Esperado: 1 asset,
   4 avaliações, 2 findings históricos e lifecycle completed/revisão 4.
3. Percorra as quatro páginas e volte à primeira. A última desabilita Próxima.
   Abra Proveniência/Evidência registrada e confira legibilidade e a cobertura.
4. Consulte `OTHER`: esperado acesso negado, relatório anterior removido.
5. Consulte novamente o assessment autorizado. Clique **Sair** e recarregue:
   esperado login, sem relatório ou conta visível. Verifique também uma janela
   estreita: formulários legíveis e tabela com rolagem própria.

## 5. Encerrar e enviar evidência

Depois de sair no navegador, pressione **Ctrl+C no Rocky**. Esperado:
`OPERATOR WEB LAB STOP PASS`, `tables_compared=14`, `database_mutated=false`,
`store_accessed=false`, servidor parado/contas removidas e
`INVARIANTES WEB VALIDADAS NESTA SESSAO: true`. Depois o bloco limpa PGPASSWORD.
STOP PASS comprova as invariantes do launcher; o aceite visual depende das telas.
Encerre o túnel na outra janela PowerShell com Ctrl+C.

Envie PACKAGE OK, READY/STOP PASS e capturas de login vazio, relatório, última
página e negação/logout. Não enviar senha, tokens, arquivo de contas ou DevTools
com cabeçalhos de autorização. Se qualquer etapa falhar, envie a mensagem visível
e a etapa; preservar o LAB e não repetir os gates anteriores.

[ADR 0024](ADR_0024_Local_Operator_Web_v0.6.12.md) · [Guia](../server/README.md).
