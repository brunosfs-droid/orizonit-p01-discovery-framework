# Cancã — LAB Optional Agent v0.5f.0 / P01LAB R1

Data: 01/10/2026. Status: LAB VALIDATED — Windows P01LAB R1; Linux coberto por CI.
Baseline: portable runtime v0.5e.6 LAB VALIDATED; Issue #83.

As 27 capturas do R1 comprovam completed-resume, progressão até upload,
FULL 5/5, receipt mTLS HTTP 201/semantic_match=true, grants separados e lock
agente/portátil. Policy inválida/identidade divergente falharam com exit 2;
Config tamper e interrupção antes de dispatch passaram no run negativo, com
state/config preservados, policy restaurada e intent mantido. Auditoria do
contrato e hashes dos journals: 17/17 no completo e 4/4 no negativo.
Artifact/target tamper PASS, 75 arquivos da origem inalterados; console da API
mostra último POST às 19:10:04, sem POST posterior exibido após os repeats.
Aceite fechado no processo/janela observados. Linux real não foi executado.
Ver [registro de evidências](validation/OPTIONAL_AGENT_P01LAB_R1_v0.5f.0.md).

## Objetivo e limites

Homologar o wrapper opcional antes de instalar serviços. Reutilizar o workspace
concluído da v0.5e para comprovar resume sem scan/AUTH/FULL/POST. Depois, criar um
run independente e validar progressão permitida e bloqueio de cada etapa live.
Nenhum serviço Windows, systemd, task agendada ou loop é instalado na v0.5f.0.

Executar no Discovery Node, com o ambiente Python já usado no LAB. Os comandos
abaixo são PowerShell, a partir da raiz do repositório. No Linux, os mesmos
subcomandos Python funcionam; adaptar apenas variáveis e caminhos do shell.
Não enviar Credential Profiles com locators/segredos, certificados privados,
variáveis de ambiente ou senha nas evidências compartilhadas.

## 1. Atualizar e identificar o workspace concluído

Após a integração da PR na main:

```powershell
git status --short
git switch main
git pull --ff-only
python agent/P01_Agent.py validate-policy --policy agent/agent-policy.example.json
```

Se o Git mostrar alterações locais, preservá-las antes de trocar a branch. A
policy de exemplo deve retornar `status: valid`; ela não concede nenhuma etapa.
Informar o workspace que terminou a v0.5e.6, contendo `state/run-state.json`:

```powershell
$Workspace = Read-Host "Caminho completo do workspace concluído v0.5e.6"
$Workspace = (Resolve-Path $Workspace).Path
$StateFile = Join-Path $Workspace "state/run-state.json"
$State = Get-Content -Raw $StateFile | ConvertFrom-Json
python runtime/P01_Discovery_Node.py status --workspace $Workspace --json
```

Esperado: upload `completed` e `next_action: complete`. Caso contrário, finalizar
a homologação portátil desse run antes do gate de completed-resume.

## 2. Policy default-deny ligada ao run existente

```powershell
$Policy = Join-Path $Workspace "config/agent-policy.json"
$PolicyDoc = @{
    schema_version = "0.5f"
    identity = @{
        assessment_id = $State.assessment_id
        run_id = $State.run_id
        node_id = $State.node_id
    }
    grants = @{
        discovery = $false; planning = $false; dry_run = $false
        auth_only = $false; full = $false; resolver = $false
        export = $false; upload = $false
    }
}
$PolicyDoc | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $Policy
python agent/P01_Agent.py validate-policy --policy $Policy
python agent/P01_Agent.py doctor --workspace $Workspace --policy $Policy
python agent/P01_Agent.py status --workspace $Workspace --policy $Policy
```

Esperado: policy válida, doctor `ready: true`, sem rede/secret resolution/AUTH;
status `already_complete`. Todos os grants permanecem falsos. Readiness verifica
pré-requisitos; não concede autorização.

## 3. Completed-resume sem inputs de transporte

```powershell
$Before = (Get-FileHash -Algorithm SHA256 $StateFile).Hash
python agent/P01_Agent.py run-once --workspace $Workspace --policy $Policy
python agent/P01_Agent.py run-once --workspace $Workspace --policy $Policy
$After = (Get-FileHash -Algorithm SHA256 $StateFile).Hash
"State unchanged: $($Before -eq $After)"
```

Esperado: duas respostas `already_complete`; nenhum parâmetro de certificado ou
key requerido; state inalterado, sem novo scan, autenticação, coleta ou POST.
Verificar também os logs de ingestão do servidor: nenhum novo POST dessa prova.
Cada chamada cria um journal separado em `logs/agent`.

```powershell
Get-ChildItem (Join-Path $Workspace "logs/agent") -Filter *.json | ForEach-Object {
    $Expected = ((Get-Content -Raw ($_.FullName + ".sha256")) -split '\s+')[0]
    $Actual = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    [pscustomobject]@{ Journal = $_.Name; SHA256_OK = ($Expected -eq $Actual) }
}
```

Esperado: SHA256_OK true para todos. Journals registram stage/status/digest e
timestamps; não devem conter senha, provider locator, key path ou erro bruto.

## 4. Criar run independente para default-deny e progressão

Reutilizar somente as referências do manifest/profiles homologados, mantendo o
run anterior concluído. Os arquivos precisam continuar disponíveis no node.

```powershell
$Manifest = $State.source_refs.assessment_manifest
$Profiles = $State.source_refs.credential_profiles
$RunsRoot = Split-Path (Split-Path $Workspace -Parent) -Parent
$NewRun = "P01LAB-AGENT-R1"
python runtime/P01_Discovery_Node.py init --workspace-root $RunsRoot `
    --assessment-id $State.assessment_id --run-id $NewRun `
    --node-id $State.node_id --manifest $Manifest --profiles $Profiles
$AgentWorkspace = Join-Path (Join-Path $RunsRoot $State.assessment_id) $NewRun
$AgentPolicy = Join-Path $AgentWorkspace "config/agent-policy.json"
$PolicyDoc.identity.run_id = $NewRun
$PolicyDoc | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
"Exit: $LASTEXITCODE"
```

Esperado: `policy_denied`, stage `discovery`, exit 3. Sem scan, secret resolution
ou autenticação. No próximo gate, selecionar explicitamente UM IP/CIDR que já
esteja autorizado no Assessment Manifest do LAB:

```powershell
(Get-Content -Raw $Manifest | ConvertFrom-Json).authorized_scopes
$ScanTarget = Read-Host "UM IP/CIDR do LAB autorizado no manifest"
if ([string]::IsNullOrWhiteSpace($ScanTarget)) { throw "Informar um IP/CIDR autorizado" }
$PolicyDoc.discovery = @{ targets = @($ScanTarget) }
$PolicyDoc.limits = @{ max_hosts = 2048; max_actions = 25 }
$PolicyDoc.grants.discovery = $true
$PolicyDoc.grants.planning = $true
$PolicyDoc.grants.dry_run = $true
$PolicyDoc | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $AgentPolicy
python agent/P01_Agent.py validate-policy --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
```

Esperado, por chamada: discovery advanced; planning advanced; dry_run advanced;
auth_only policy_denied. Uma chamada nunca executa toda a sequência. Planejamento
e dry-run não resolvem secrets nem autenticam. Os escopos/exclusões do manifest
continuam valendo; grant não amplia o alcance autorizado.

## 5. Grants independentes de AUTH, FULL e upload

Antes de habilitar AUTH, garantir providers não interativos `wincred://` ou
`env://` acessíveis à identidade atual, e SSH known_hosts já conhecido (strict).
Profiles que contêm `prompt://` bloqueiam AUTH/FULL nesta versão. Não alterar
profiles depois do plan/preview; drift exige revisão pelo fluxo portátil.

```powershell
$PolicyDoc.grants.auth_only = $true
$PolicyDoc | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
```

Esperado: AUTH advanced uma vez; depois FULL policy_denied. Se ocorrer falha ou
resultado parcial, preservar evidência: próximas chamadas devem retornar
review_required e nunca repetir AUTH automaticamente. Corrigir/recuperar através
do procedimento portátil explícito antes de continuar.

```powershell
$PolicyDoc.grants.full = $true
$PolicyDoc.grants.resolver = $true
$PolicyDoc.grants.export = $true
$PolicyDoc | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
```

Esperado: FULL advanced; resolver advanced; export advanced; upload policy_denied.
Resolver/export são locais; nenhuma coleta FULL anterior se repete. Pode encerrar
o fluxo aqui e transportar o bundle manualmente.

Para testar upload, conceder `upload: true` na policy e passar os quatro inputs
mTLS apenas nessa invocação. Usar a URL/FQDN e os certificados já homologados:

```powershell
$PolicyDoc.grants.upload = $true
$PolicyDoc | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
```

Esperado: transport_required, exit 2, nenhum POST. Depois, com os caminhos reais:

```powershell
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy `
    --server-url "https://FQDN-DO-SERVIDOR:8443" `
    --ca-cert "CAMINHO-CA.crt" --client-cert "CAMINHO-NODE.crt" `
    --client-key "CAMINHO-NODE.key"
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
```

Substituir placeholders antes de executar. Esperado: upload advanced com receipt
do runtime e semantic_match true; depois already_complete, sem segundo POST.
Private key continua invocation-only. Policy/journal não guardam transporte.

## 6. Negative gates e lock

Policy inválida: criar outro JSON com schema_version desconhecido ou grant como
string. run-once deve falhar invalid_policy, exit 2, sem live action. Policy de
outro run/node deve falhar workspace_identity_mismatch.

Integridade: em um run de teste parado, guardar bytes exatos de runtime.json,
alterar o arquivo sem atualizar seu sidecar e chamar doctor/run-once. Esperado
workspace_integrity_failed. Restaurar os bytes originais; nunca recalcular hash
para ocultar adulteração. Repetir com um artifact/target FULL de um run de teste.

Lock em duas janelas, na raiz do repositório. Definir os caminhos e ativar o
ambiente em CADA janela: variáveis PowerShell não são compartilhadas. Janela 1:

```powershell
Set-Location "C:\GitHub\orizonit-p01-discovery-framework"
. .\.venv\Scripts\Activate.ps1
$AgentWorkspace = "C:\Canca\runs\P01LAB-CTX-R1\P01LAB-AGENT-R1"
$HoldScript = @'
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "runtime"))
from P01_Workspace_Lock import workspace_lock
with workspace_lock(Path(sys.argv[1])):
    print("LOCK HELD", flush=True)
    input("Press Enter to release: ")
'@
$HoldFile = Join-Path $env:TEMP "p01_hold_workspace_lock.py"
$HoldScript | Set-Content -Path $HoldFile -Encoding UTF8
python $HoldFile $AgentWorkspace
```

Usar o arquivo `.py`: `python -c $HoldScript` perdeu aspas na execução real com
Windows PowerShell e gerou SyntaxError antes de adquirir o lock.

Janela 2, enquanto a primeira mostra LOCK HELD:

```powershell
Set-Location "C:\GitHub\orizonit-p01-discovery-framework"
. .\.venv\Scripts\Activate.ps1
$AgentWorkspace = "C:\Canca\runs\P01LAB-CTX-R1\P01LAB-AGENT-R1"
$AgentPolicy = Join-Path $AgentWorkspace "config/agent-policy.json"
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python runtime/P01_Discovery_Node.py run --workspace $AgentWorkspace
```

Esperado workspace_busy nos dois comandos, antes da mutação. Este gate já foi
comprovado no R1 (capturas 213612 e 213854); não é necessário repeti-lo.
Um journal `running` após queda do processo também exige revisão. Verificar os
checkpoints e, para upload, receipt/idempotency no servidor antes da recuperação
portátil explícita. Preservar e arquivar o intent revisado fora de logs/agent antes
de retomar o agente; não simplesmente excluir o intent para repetir acesso.

Liberar com Enter e verificar que o status passa a funcionar. O arquivo de lock
permanece; não excluí-lo. Encerrar o processo também libera o lock pelo kernel.

```powershell
python agent/P01_Agent.py status --workspace $AgentWorkspace --policy $AgentPolicy
python runtime/P01_Discovery_Node.py status --workspace $AgentWorkspace --json
```

O [registro R1](validation/OPTIONAL_AGENT_P01LAB_R1_v0.5f.0.md) contém a prova mTLS
concluída, policy/config tamper/interrupção/auditoria aprovados e o próximo comando
do LAB Windows Service v0.5f.1; artifact/target tamper já aprovado. Não repetir os gates
live concluídos para coletar esses negativos.

## Critério de aceite e evidências

- [x] doctor offline; policy versionada válida e grants ausentes negados;
- [x] completed workspace: already_complete, state inalterado, nenhum novo POST;
- [x] discovery/planning/dry-run avançam uma vez cada; parada antes de AUTH;
- [x] AUTH e FULL dependem de grants distintos; nenhuma repetição silenciosa;
- [x] resolver/export avançam; upload negado ou transport_required sem inputs;
- [x] mTLS autorizado conclui; repeat upload não faz POST;
- [x] JSON/SHA256 journal íntegro e sem segredos/key paths/erros brutos;
- [x] policy inválida/identity mismatch/integridade falham fechadas;
- [x] duas instâncias e agente vs portátil bloqueados pelo lock;
- [x] interrupção antes de dispatch exige revisão e bloqueia replay; intent preservado;
- [x] nenhum serviço/tarefa/cron instalado nesta versão.

Completed-resume/upload e integridade aprovados nas 27 capturas. O console da
API não exibe POST posterior aos repeats na execução observada; a fixture de
tamper preservou o run completo. O gate de interrupção acima
tem a fronteira pre-dispatch; não comprova queda durante AUTH/FULL ou após POST.

Enviar outputs/prints de doctor, status, resume, gates e hashes; journals e seus
sidecars; run-state e sidecar; receipt sanitizado e confirmação de logs do server.
Não incluir secret locators ou private key. CI usa fixtures/mock de transporte;
não substitui este aceite Windows/Linux e mTLS real.

Aceite Windows concluído em 01/10/2026: v0.5f.0 LAB VALIDATED.
Próximo roteiro: [LAB Windows Service v0.5f.1](LAB_WINDOWS_SERVICE_v0.5f.1_R1.md).
