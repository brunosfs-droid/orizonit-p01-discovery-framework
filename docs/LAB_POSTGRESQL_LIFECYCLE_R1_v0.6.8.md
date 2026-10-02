# P01 — lifecycle e paginação R1 v0.6.8

R1 básico e recuperação estão aprovados. Não repetir instalação, migração, dump ou restore.
Este gate utiliza somente a base recuperada canca_p01_restore_r1; quatro mudanças administrativas
serão gravadas explicitamente. Fonte/store original e API ativa ficam preservados. Sem AUTH/FULL/POST.
Executar em janela sem outros escritores na fixture. Código/CI segue independente do resultado LAB.

**Correção em 02/10/2026, após capturas 215506/215725/215911:** o helper foi instalado
corretamente, mas o sufixo do diretório foi transcrito incorretamente neste roteiro.
`test -f` não exibiu REFERENCIA OK e inspect/exercise retornaram recovery_invalid antes
da conexão. Lifecycle/paginação ainda não estão aprovados no LAB. Começar na etapa 2
abaixo; não reenviar helper, restaurar banco ou recriar snapshot para resolver o caminho.

## 1. Enviar somente o helper novo

No PowerShell, já no clone Cancã, usar o SHA qualificado informado na entrega no lugar de SHA_V068_QUALIFICADO:

```powershell
git fetch origin
$P01Release = 'SHA_V068_QUALIFICADO'
git archive --format=tar --output "$env:TEMP\canca-lab-v0.6.8-helper.tar" $P01Release docs/validation/POSTGRESQL_LAB_LIFECYCLE_R1_v0.6.8.py
Get-FileHash "$env:TEMP\canca-lab-v0.6.8-helper.tar" -Algorithm SHA256
scp "$env:TEMP\canca-lab-v0.6.8-helper.tar" root@192.168.100.50:/root/p01/
```

Rocky, root: conferir o SHA do tar contra Windows. Copiar apenas helper para o deployment original,
preservando P01_Findings.py e os demais módulos com bytes CRLF já qualificados:

```bash
sha256sum /root/p01/canca-lab-v0.6.8-helper.tar
P01_HELPER_DIR=$(mktemp -d /root/p01/canca-helper-v0.6.8-XXXXXXXX)
tar -xf /root/p01/canca-lab-v0.6.8-helper.tar -C "$P01_HELPER_DIR"
export P01_HELPER_DIR
python3 - <<'PY'
import os
from pathlib import Path
source = Path(os.environ['P01_HELPER_DIR'])/'docs/validation/POSTGRESQL_LAB_LIFECYCLE_R1_v0.6.8.py'
target = Path('/root/p01/canca-postgres-lab-v0.6.5/docs/validation')/source.name
if target.exists():
    assert target.read_bytes() == source.read_bytes(), 'Helper existente diferente; revisar sem overwrite'
else:
    with target.open('xb') as output:
        output.write(source.read_bytes())
print('HELPER OK')
PY
cd /root/p01/canca-postgres-lab-v0.6.5
source .venv/bin/activate
sha256sum persistence/P01_Findings.py
```

Engine original esperado: 57c0b7834095d00512e6046bd884c03556f46738e97d7fdb4dcb9847efcc2365.
Não substituir esse engine por outra cópia, normalizar line endings ou editar fingerprints.
Helper de recuperação v0.6.7 já está instalado junto ao helper novo.

## 2. Restaurar variáveis e consultar sem escrever

Localizar o snapshot original pelo SHA256 aceito, sem copiar o sufixo de uma imagem.
O bloco abaixo valida JSON/sidecar pelo helper já instalado e exige exatamente uma
referência correspondente e o diretório restored-store. Não acessa PostgreSQL nem grava arquivos.
Se houver zero/múltiplas referências ou erro de integridade, ele para sem selecionar a primeira.
Copiar o bloco inteiro no Rocky, na mesma sessão em que os próximos comandos serão executados:

```bash
unset PGSERVICE PGHOSTADDR
export PGHOST=127.0.0.1
export PGPORT=5432
export PGUSER=canca_lab_admin
export PGDATABASE=canca_p01_restore_r1
unset P01_RECOVERY_DIR P01_RESTORED_STORE P01_REFERENCE
P01_INSPECT_OK=false
cd /root/p01/canca-postgres-lab-v0.6.5
source .venv/bin/activate
if P01_REFERENCE="$(python3 - <<'PY'
import hashlib
import importlib.util
from pathlib import Path
import sys

root = Path('/var/lib/canca/postgres-recovery')
expected = '13e1473ceab9f6e636ac1709db455ac34a8377b8b63c5e889d86a534685d3fb8'
try:
    helper = Path('docs/validation/POSTGRESQL_LAB_RECOVERY_R1_v0.6.7.py').resolve()
    spec = importlib.util.spec_from_file_location('locate_recovery_r1', helper)
    recovery = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recovery)
    candidates = []
    for number, path in enumerate(root.glob('P01-PG-RECOVERY-*/source-proof/P01-PG-RECOVERY-*/snapshot.json'), 1):
        if number > 100:
            raise ValueError('limit')
        with path.open('rb') as source:
            raw = source.read(1024**2 + 1)
        if len(raw) <= 1024**2 and hashlib.sha256(raw).hexdigest() == expected:
            recovery.load_snapshot(path)
            store = path.parents[2] / 'restored-store'
            if not store.is_dir() or store.absolute() != store.resolve():
                raise ValueError('store')
            candidates.append(path)
    if len(candidates) != 1:
        raise ValueError('reference_count')
    print(candidates[0])
except Exception:
    print('LOCALIZACAO FALHOU: revisar referencia/store; nenhuma alteracao realizada.', file=sys.stderr)
    raise SystemExit(2)
PY
)"; then
  export P01_REFERENCE
  P01_RECOVERY_DIR="$(dirname "$(dirname "$(dirname "$P01_REFERENCE")")")"
  export P01_RECOVERY_DIR
  export P01_RESTORED_STORE="$P01_RECOVERY_DIR/restored-store"
  printf 'Referencia: %s\nStore recuperado: %s\n' "$P01_REFERENCE" "$P01_RESTORED_STORE"
  echo 'REFERENCIA OK — JSON, sidecar e SHA original conferidos'
  read -r -s -p 'Senha canca_lab_admin: ' P01_LAB_PASSWORD
  export PGPASSWORD="$P01_LAB_PASSWORD"
  unset P01_LAB_PASSWORD
  if python docs/validation/POSTGRESQL_LAB_LIFECYCLE_R1_v0.6.8.py inspect \
    --expected-database canca_p01_restore_r1 --store-dir "$P01_RESTORED_STORE" \
    --reference "$P01_REFERENCE" --evidence-root "$P01_RECOVERY_DIR/lifecycle-proof"; then
    P01_INSPECT_OK=true
  else
    unset PGPASSWORD
    echo 'PARAR: inspect falhou; nao executar exercise.'
  fi
else
  unset P01_REFERENCE
  echo 'PARAR: nao executar inspect/exercise antes de localizar a referencia.'
fi
```

Esperado: POSTGRESQL LAB PAGES PASS, state registered/revision 0, report_pages=4,
evaluations=4, recorded_open_findings=2, unchanged_tables_compared=12,
source_bytes_revalidated=true, administrative_lifecycle_mutated=false, store_mutated=false.
inspect também aceita um prefixo já confirmado do teste se houve interrupção posterior.
**Só executar etapa 3 depois de POSTGRESQL LAB PAGES PASS/exit 0.** Se a localização
ou inspect falhar, enviar esse resultado e não avançar para exercise.

## 3. Exercício explícito na base recuperada

```bash
if [ "${P01_INSPECT_OK:-false}" = true ]; then
  python docs/validation/POSTGRESQL_LAB_LIFECYCLE_R1_v0.6.8.py exercise \
    --expected-database canca_p01_restore_r1 --store-dir "$P01_RESTORED_STORE" \
    --reference "$P01_REFERENCE" --evidence-root "$P01_RECOVERY_DIR/lifecycle-proof" \
    --ack-lifecycle-test
else
  echo 'PARAR: concluir a etapa 2 com inspect PASS nesta mesma sessao.'
fi
```

Primeira execução inteira: POSTGRESQL LAB LIFECYCLE PASS, initial_revision=0,
state completed/revision 4, transitions_applied=4, stale_cursor_rejections=4,
idempotent_replays=4, negative_transition_gates=3, report_pages=4, evaluations=4.
Os erros de request diferente, revisão antiga e reabrir terminal são esperados e
verificados internamente; PASS inclui as três negações e quatro páginas do histórico.

Salvar JSON exibido e proof_path/proof_sha256. O diretório novo contém snapshot.json
e snapshot.json.sha256 privados, com resultado e captura final. Se houver falha,
encaminhar o código fixo e o resultado anterior; nenhum dado é corrigido automaticamente.
Commits anteriores permanecem; o mesmo comando retoma somente a sequência reconhecida.

## 4. Reexecutar para verificar ausência de eventos duplicados

Executar novamente o comando exercise da etapa 3. Esperado: PASS, initial_revision=4,
transitions_applied=0, stale_cursor_rejections=0, administrative_lifecycle_mutated=false,
4 replays e 3 negações; state completed/revision 4. Este PASS não substitui a evidência
da primeira execução de invalidação de cursor. Ao terminar:

```bash
unset PGPASSWORD
```

Encaminhar capturas dos resultados inspect, primeiro exercise e replay, ou JSONs/proofs
sem credenciais. Não precisa repetir testes de serviço, backup/restore ou reader.
Snapshot de recuperação original representa registered/revisão 0: após lifecycle, a
comparação integral do helper v0.6.7 contra ele deve divergir nas duas tabelas alteradas.
O helper v0.6.8 compara explicitamente as outras 12 e valida o histórico permitido.
completed é administrativo; findings históricos continuam Open. TLS remoto e roles
separados do owner não são qualificados por este teste.
