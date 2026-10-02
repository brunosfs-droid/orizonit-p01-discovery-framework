# Cancã — LAB Linux/systemd v0.5f.2 / P01LAB R1

Data: 01/10/2026 (-03). Status: CANDIDATE; aceite Rocky Linux pendente.
Host P01-LNX-RKY01 (192.168.100.50), separado do Windows P01-MGMT01.
Ensaio offline de lifecycle, sem discovery/AUTH/FULL/POST. Mantém a API de ingestão
em execução e o store já validado; nenhum comando abaixo opera esse serviço.

## 1. Preparar o código no Windows

PowerShell na raiz do repositório. Após a integração da PR, atualizar main e
exportar somente arquivos versionados necessários ao ensaio (sem PKI/secrets):

```powershell
Set-Location "C:\GitHub\orizonit-p01-discovery-framework"
git pull origin main
if ($LASTEXITCODE -ne 0) { throw "Falha no git pull." }
$LinuxArchive = Join-Path $env:TEMP "canca-agent-v0.5f.2.tar"
git archive --format=tar --output=$LinuxArchive HEAD agent runtime tests docs
if ($LASTEXITCODE -ne 0) { throw "Falha ao exportar o código versionado." }
scp $LinuxArchive root@192.168.100.50:/root/p01/canca-agent-v0.5f.2.tar
if ($LASTEXITCODE -ne 0) { throw "Falha na transferência para o Rocky." }
```

Se o Rocky já tiver checkout atualizado desse repositório, usar essa raiz e
dispensar a transferência. Não usar o diretório da API como deployment do agente.

## 2. Executar no Rocky como root

Usar outro terminal, mantendo a console da API aberta. O Python escolhido deve
ser 3.9+ e estar fora de /root ou /home; não usar a venv da API. Validar as versões:

```bash
cat /etc/os-release
/usr/bin/python3 --version
systemctl --version
cat /proc/1/comm
getenforce
```

PID 1 deve ser systemd. Se Python <3.9, usar um interpretador 3.9+ já instalado
fora dos diretórios protegidos. Não alterar o Python/venv da ingestão.

```bash
mkdir -p /root/p01/canca-agent-v0.5f.2
tar -xf /root/p01/canca-agent-v0.5f.2.tar -C /root/p01/canca-agent-v0.5f.2
cd /root/p01/canca-agent-v0.5f.2
/usr/bin/python3 tests/linux_service_systemd_smoke.py \
  --lab-root /var/lib/canca/service-lab --node-id P01-LNX-RKY01
LabExit=$?
printf 'Exit LAB: %s\n' "$LabExit"
```

O helper recusa qualquer canca-p01-agent.service preexistente antes de instalar.
Cria/valida apenas a conta dedicada canca-agent (sem login/grupos suplementares),
fixture única P01-SYSTEMD-R1-..., e deployment mínimo fora de /root. A fixture
fica em /var/lib/canca/service-lab; código/config/policy root-owned; apenas
outputs/state/logs/lock pertencem à conta. Todos os grants permanecem negados
salvo a preparação temporária do intent, encerrada antes de dispatch real.
Sem manifests/profiles/PKI. O deployment mínimo serve somente para este ensaio;
não é uma instalação completa para discovery ou etapas live.

## 3. Conferir e preservar

Esperado: LINUX SYSTEMD SMOKE PASS, exit 0, service_version=0.5f.2, starts=4,
one_invocation_per_start=true, policy_denied_starts=2, review_required_starts=2,
idle_repeat=false, automatic_recovery_enabled=false, source_state_unchanged=true,
intent_preserved=true, lock_reacquired=true, service_removed=true,
journal_audit=JOURNAL AUDIT PASS (7 journals), evidence_retained=true.

Sequência: instalar/start negado; recusar remove enquanto ativo; stop/restart
negado; stop; criar intent em processo filho com queda pre-dispatch; start exige
revisão; SIGKILL somente no MainPID do host de teste ocioso; verificar failed sem
restart automático na janela observada e lock liberado; quarto start manual
continua review_required; stop/audit/remove. A interrupção do host ocorre ocioso;
não comprova cancelamento de AUTH/FULL ou reconciliação de POST.

Enviar captura das versões e do resumo inteiro incluindo fixture_directory,
evidence_retained e Exit LAB. Guardar linux-service-proof.json + SHA256, os sete
journals/sidecars, backup da policy e intent running dentro da fixture. Não
apagar o intent para liberar replay. Conta e fixture permanecem após remove;
nenhuma unidade fica instalada ao passar. Repetição usa outra fixture.

## Falha e limpeza

Preservar output/fixture. Examinar somente a unidade do ensaio:

```bash
systemctl status canca-p01-agent.service --no-pager
journalctl -u canca-p01-agent.service -n 60 --no-pager
```

Se houver AVC/SELinux, preservar o diagnóstico; não desativar SELinux nem ampliar
grants/ownership da API para passar. Uma falha de ambiente não fecha o aceite.
O helper tenta stop/remove em finally. Para concluir limpeza, usar o mesmo
interpretador e deployment/config impressos na fixture, substituindo o caminho:

```bash
Fixture=/var/lib/canca/service-lab/P01-SYSTEMD-R1-<identificador>
/usr/bin/python3 "$Fixture/deployment/agent/P01_Linux_Service.py" query --config "$Fixture/service.json"
/usr/bin/python3 "$Fixture/deployment/agent/P01_Linux_Service.py" stop --config "$Fixture/service.json"
# Após query indicar inactive/failed e main_pid=0:
/usr/bin/python3 "$Fixture/deployment/agent/P01_Linux_Service.py" remove --config "$Fixture/service.json"
```

Stop durante invocação aguarda conclusão; não há timeout de kill automático.
Não habilitar unit/timer/recovery. Este aceite cobre lifecycle e revisão manual;
credenciais live, cancelamento e scheduling/recovery/soak terão gates próprios.
