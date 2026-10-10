# Cancã — LAB agendador v0.5f.3 / R1 Windows e Rocky

Guia criado: 01/10/2026 (-03). R1 aceito: 02/10/2026 (-03).
Status: LAB VALIDATED para o ensaio offline abaixo em Windows e Rocky.
[Registro e limites do aceite](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md).
Ensaio offline em fixture nova, com todos os grants negados. Sem discovery, AUTH,
FULL ou POST. Não opera a API de ingestão nem o store. Tempo padrão: pouco mais
que 60 segundos por host; o terminal fica ocupado aguardando o intervalo real.

O helper recusa um serviço preexistente antes de criar/instalar. Não remover um
serviço alheio para passar. Se uma instalação antiga estiver presente, usar o código
e a config originais para stop/query/remove antes de atualizar o deployment.
Após PASS, os serviços já foram removidos. Preservar as fixtures aprovadas;
repetições criam outra fixture, sem apagar intent de revisão.

## Windows — P01-MGMT01

PowerShell elevado, mesmo checkout/venv do R1 manual. Confirmar os comandos sem erro:

```powershell
Set-Location "C:\GitHub\canca"
git pull origin main
if ($LASTEXITCODE -ne 0) { throw "Falha no git pull." }
. .\.venv\Scripts\Activate.ps1
python --version
python -m pip install -r agent/requirements-windows-service.txt
if ($LASTEXITCODE -ne 0) { throw "Falha na dependência SCM." }
python tests/scheduled_agent_soak.py --lab-root "C:\Canca\scheduled-lab" --node-id P01-MGMT01
$LabExit = $LASTEXITCODE
Write-Host "Exit LAB Windows: $LabExit"
if ($LabExit -ne 0) { throw "Preservar output/fixture da falha." }
```

Cria fixture P01-SCHEDULED-R1-..., instala CancaP01Agent manual/LocalService sem
recovery e ajusta ACL do SID para leitura de deployment/interpreter/config e escrita
somente nos diretórios mutáveis e lock. O código/policy/config ficam fora do contexto
de escrita do serviço. O helper ativa explicitamente o scheduler após instalar.
Não reaproveitar a fixture de interrupção para outra rodada.

## Transferir código versionado para o Rocky

No mesmo PowerShell, depois do git pull acima. O destino /root/p01 já é o usado no LAB:

```powershell
$LinuxArchive = Join-Path $env:TEMP "canca-agent-v0.5f.3.tar"
git archive --format=tar --output=$LinuxArchive HEAD agent runtime tests docs
if ($LASTEXITCODE -ne 0) { throw "Falha no archive." }
scp $LinuxArchive root@192.168.100.50:/root/p01/canca-agent-v0.5f.3.tar
if ($LASTEXITCODE -ne 0) { throw "Falha no SCP." }
```

## Rocky — P01-LNX-RKY01

Outro terminal root, mantendo a API existente aberta. Usar /usr/bin/python3 3.10+,
sem venv da ingestão. No R1 manual: Rocky 10.2/Python 3.12.13/systemd 257.

```bash
cat /etc/os-release
LinuxPython=/usr/bin/python3
"$LinuxPython" --version
"$LinuxPython" -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ necessario"'
systemctl --version
cat /proc/1/comm
getenforce
mkdir -p /root/p01/canca-agent-v0.5f.3
tar -xf /root/p01/canca-agent-v0.5f.3.tar -C /root/p01/canca-agent-v0.5f.3
cd /root/p01/canca-agent-v0.5f.3
"$LinuxPython" tests/scheduled_agent_soak.py \
  --lab-root /var/lib/canca/scheduled-lab --node-id P01-LNX-RKY01
LabExit=$?
printf 'Exit LAB Rocky: %s\n' "$LabExit"
```

Prosseguir somente com Python 3.10+ e PID 1 systemd. Helper valida/cria canca-agent,
stageia o core mínimo root-owned em /var/lib, concede escrita apenas a outputs/state/
logs/lock e usa a unit estática protegida. Esse core mínimo atende somente o teste
de lifecycle negado. Não desativar SELinux para passar nem mudar ownership da API.

## Critérios e evidências em ambos os hosts

Esperado: **SCHEDULED AGENT SOAK PASS**, exit 0, service_version/scheduler_version
0.5f.3, starts=3, scheduled_ticks=2, real_interval_seconds=60,
bounded_cycle_elapsed_seconds >=60, policy_reread=true, all_grants_denied=true,
source_state_unchanged=true, budget_idles_host=true, automatic_recovery_enabled=false,
interrupted_wait_intent_preserved=true, restart_review_invocations=0,
lock_reacquired=true, service_removed=true, evidence_retained=true.

journal_audit: JOURNAL AUDIT PASS, 3 journals válidos. scheduler_audit:
SCHEDULER AUDIT PASS, 3 sessões, unfinished_session=true e review_required=true.
Esses dois últimos campos são esperados: o segundo start foi morto durante a espera;
seu intent permanece running e o terceiro registra review_required sem nova invocação.
Isso prova bloqueio do scheduler mesmo sem intent canônico de dispatch interrompido.

Capturar versão/commit (`git rev-parse HEAD` no Windows), resumo inteiro e Exit LAB de
cada host, incluindo fixture_directory. Preservar scheduled-agent-proof.json e SHA256,
service.json, policy e as duas famílias de journal/sidecars dentro de cada fixture.
Por padrão são três tentativas negadas e três sessões por host. O helper verifica
hashes, campos, identidade, intervalo real, state intacto e ausência de restart na
janela observada. O orçamento termina; o serviço só sai do idle quando parado.

Para observação adicional, --ticks 10 estende o primeiro ciclo a pelo menos nove
minutos e produz 11 journals canônicos (10 + 1), mantendo três sessões. R1 padrão
curto não estabelece estabilidade multi-day, execução live ou cancelamento de POST.
Não substituir as capturas padrão por resultados de relógio acelerado dos unit tests.

## Inspeção após PASS ou falha

Após PASS, serviço ausente é esperado; não reinstalar para consultar evidências.
Se falhar, preservar o traceback/output e a fixture. Helper tenta parar/remover
somente a instalação que criou. Não apagar intent para liberar outro start.
No Windows, Get-Service CancaP01Agent e Application Event Log permitem inspecionar
somente esse host; uma ausência pós-PASS é normal.

No Rocky, journal histórico permanece após remoção:

```bash
journalctl -u canca-p01-agent.service -n 80 --no-pager
read -r -p 'Cole o fixture_directory exibido no resumo: ' Fixture
if [ -f "$Fixture/service.json" ]; then
  "$LinuxPython" "$Fixture/deployment/agent/P01_Linux_Service.py" query --config "$Fixture/service.json"
else
  printf 'Fixture sem service.json; conferir caminho antes de continuar.\n'
fi
```

Se query mostra installed=false, encerrar a limpeza. Em falha com serviço instalado,
usando essa config validada, stop e confirmar inactive/failed sem PID antes de remove.
Preservar fixture e conta. Mensagens 9/KILL no segundo start são a interrupção
intencional; uma falha anterior não constitui PASS.


## Fixtures do R1 aprovado

Windows: C:\Canca\scheduled-lab\P01-SCHEDULED-R1-74eab0f492e9.
Rocky: /var/lib/canca/scheduled-lab/P01-SCHEDULED-R1-69e3e937d4c7.
PASS/exit 0 em ambos, 3 journals e 3 sessões por host; ciclos de 60,525s/60,174s.
A query final no Rocky mostrou installed=false e main_pid=0: encerrar a limpeza.
Soak estendido com --ticks 10 permanece pendente e deve usar uma nova fixture.
