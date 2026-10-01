# Cancã — Optional Agent v0.5f.0 / evidências P01LAB R1

Revisão: 01/10/2026. **CANDIDATE — validação Windows parcial.**
Implementação: PR #84, main `b85746a38295def054a3822fb152086fae9ef3b2`.
Fonte: 17 capturas fornecidas pelo operador; resultados observados, sem execução
remota pelo Codex. CI Windows/Ubuntu já aprovada na implementação, com fixtures
para live AUTH/upload; não substitui os gates reais abaixo.

## Identidade e ambiente

| Campo | Valor observado |
|---|---|
| Discovery Node | P01-MGMT01 / Windows / Python 3.13.15 |
| Repositório | `C:\GitHub\orizonit-p01-discovery-framework` |
| Assessment | P01LAB-CTX-R1 |
| Run portátil concluído | P01LAB-RUNTIME-R3 |
| Novo run do agente | P01LAB-AGENT-R1 |
| Workspace novo | `C:\Canca\runs\P01LAB-CTX-R1\P01LAB-AGENT-R1` |
| Policy nova | `config\agent-policy.json` no workspace novo |
| Runtime reutilizado | v0.5e.6 |
| Agente | v0.5f.0 |

## Mapeamento exato das capturas

Arquivos no pacote de evidências: `screenshots/image(20261001-HHMMSS).png`.
O índice SHA256 do pacote protege os bytes coletados; não valida as informações
exibidas pelo host nem substitui sidecars dos journals.

| HHMMSS | Resultado comprovado pela captura |
|---|---|
| 205702 | Run portátil íntegro; resolver 5 Network + 4 FULL -> 5 logical, 0 unresolved/ambiguous/conflicts; FULL 4/4 collected e AUTH 4/4. |
| 205713 | Run portátil: export completed, 7 payload artifacts; upload completed HTTP 201/imported, semantic_match=true, mTLS e node P01-MGMT01. Não é upload do novo run do agente. |
| 205753 | Run portátil: 8 referências de artifacts existentes/com hash correspondente; next_action complete; flags de segredos persistidos falsas. |
| 205915 | Policy válida; doctor ready=true/already_complete; flags network/secret/auth falsas. |
| 205928 | Doctor: schedule_installed=false e os_service_installed=false. |
| 205955 | Status do agente no run portátil: already_complete. |
| 210629 | Duas invocações run-once no run portátil: already_complete; journals separados. |
| 210724 | State unchanged=True; SHA256_OK=True nos dois journals da prova de resume. |
| 210908 | Novo run inicializado; discovery negada por policy, exit 3. |
| 211447 | Após entrada vazia, operador definiu 192.168.100.0/24 explicitamente e habilitou discovery/planning/dry_run. Manifest mostra o mesmo escopo autorizado. |
| 211619 | Policy válida; discovery encontra 5 hosts, 0 errors; discovery/planning/dry_run avançam por invocações distintas; AUTH policy_denied. |
| 211741 | Grant AUTH habilitado: auth_only advanced; FULL ainda policy_denied. |
| 212046 | FULL/resolver/export advanced em chamadas distintas; upload policy_denied. |
| 213612 | Grant upload habilitado sem inputs mTLS: transport_required; lock em outra janela bloqueia agente com workspace_busy. |
| 213642 | python -c perdeu aspas no Windows PowerShell; operador criou arquivo .py e conseguiu LOCK HELD. Corrigido no roteiro. |
| 213854 | Sob lock: agente e portátil workspace_busy. Após liberação: status ready/upload, runtime state_integrity=true; resolver 5 Network + 5 FULL -> 5 logical, 0 unresolved/ambiguous/conflicts; 5 plan candidates. |
| 213936 | Após liberar o lock, run-once sem transporte continua transport_required. Resultado esperado para upload pendente. |

Journals da prova no run concluído: `49adc374-0001-45e2-bdd3-39bc55befe93`
e `702c2071-9bb9-41eb-ac8d-e99e325c6232`. Os hashes foram exibidos como válidos;
os arquivos originais não foram recebidos nesta revisão.

## Decisão de aceite

| Gate | Situação |
|---|---|
| Doctor/status e policy válida | Comprovados no Windows |
| Resume do run concluído | Comprovado no cliente; state inalterado e dois hashes válidos; confirmação de nenhum POST nos logs do servidor pendente |
| Default-deny e grants separados | Discovery/AUTH/FULL/upload negados nos respectivos checkpoints |
| Progressão unitária | Comprovada de discovery até export |
| Resolver real no novo run | Comprovado: 5 logical, zero unresolved/ambiguous/conflicts |
| Lock agente e portátil | Comprovado com bloqueio e liberação; não comprova encerramento abrupto do processo |
| Ausência de serviço/agendamento | Comprovada pelos flags do doctor |
| Upload mTLS do agente e repeat sem novo POST | Pendente; receipt de P01LAB-RUNTIME-R3 pertence ao baseline |
| Journals do novo run íntegros/sanitizados | Pendente; dois hashes do run antigo não cobrem o novo run inteiro |
| Policy inválida / identidade divergente / tamper | Pendentes de evidência real |
| Interrupção com intent running / review_required | Pendente de evidência real em run isolado |
| Linux real | Não executado nesta rodada; CI Ubuntu passou |

Retém CANDIDATE. Não inicia instalação do Windows Service v0.5f.1 até o fechamento
do aceite definido no roteiro. As capturas não fornecem o resumo completo de
FULL do novo run; não atribuir a ele o resultado 4/4 do run portátil anterior.

## Próximo gate: upload mTLS do P01LAB-AGENT-R1

Não repetir discovery/AUTH/FULL/export, nem reinicializar o workspace. Seu próximo
checkpoint já é upload. `transport_required` informa a ausência dos quatro
inputs de transporte dessa invocação; não indica falha do lock ou do export.

Os caminhos PKI abaixo foram usados na homologação anterior. Confirmar sua
existência antes de usar; o script para se faltarem arquivos. Não enviar a key.

```powershell
Set-Location "C:\GitHub\orizonit-p01-discovery-framework"
. .\.venv\Scripts\Activate.ps1
$AgentWorkspace = "C:\Canca\runs\P01LAB-CTX-R1\P01LAB-AGENT-R1"
$AgentPolicy = Join-Path $AgentWorkspace "config/agent-policy.json"
$PKI = "C:\P01\pki-v05d-r1"
foreach ($Name in @("ca.crt", "p01-mgmt01.crt", "p01-mgmt01.key")) {
    if (-not (Test-Path -LiteralPath (Join-Path $PKI $Name) -PathType Leaf)) {
        throw "Arquivo PKI ausente: $Name. Confirmar o diretório usado no LAB."
    }
}
python agent/P01_Agent.py status --workspace $AgentWorkspace --policy $AgentPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy `
    --server-url "https://P01-LNX-RKY01.p01.lab.test:8443" `
    --ca-cert "$PKI\ca.crt" --client-cert "$PKI\p01-mgmt01.crt" `
    --client-key "$PKI\p01-mgmt01.key"
if ($LASTEXITCODE -ne 0) { throw "Upload não concluiu; preservar o resultado antes de continuar." }
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $AgentPolicy
python runtime/P01_Discovery_Node.py status --workspace $AgentWorkspace --json
```

Esperado: upload advanced; receipt do novo run com semantic_match=true e node
P01-MGMT01; repetição already_complete sem pedir certificados; state upload
completed e next_action complete. Confirmar nos logs de ingestão que a repetição
não gerou outro POST. Preservar receipt e sidecar do workspace. Em falha ou
review_required, preservar outputs/journals e revisar antes de nova tentativa.

As capturas mostram timestamps de journal em `2026-10-02T00:06...Z` e
`00:15...Z`, enquanto os nomes são de 01/10 às 21h. Conferir data/fuso e
sincronização do node, sem concluir a causa apenas pelos nomes de arquivo:

```powershell
Get-Date
(Get-Date).ToUniversalTime()
Get-TimeZone
w32tm /query /status
```

## Fechamento dos negativos e journals

Com o run parado, os testes de policy usam cópias temporárias; não alteram a
policy real. O grant upload é explicitamente negado nas cópias.

```powershell
$BadPolicy = Join-Path $env:TEMP "p01_agent_invalid_policy.json"
$Bad = Get-Content -Raw $AgentPolicy | ConvertFrom-Json
$Bad.grants.upload = $false
$Bad.schema_version = "invalid-test"
$Bad | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $BadPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $BadPolicy
"Exit invalid policy: $LASTEXITCODE"

$MismatchPolicy = Join-Path $env:TEMP "p01_agent_identity_mismatch.json"
$Mismatch = Get-Content -Raw $AgentPolicy | ConvertFrom-Json
$Mismatch.grants.upload = $false
$Mismatch.identity.run_id = "P01LAB-OTHER-RUN"
$Mismatch | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $MismatchPolicy
python agent/P01_Agent.py run-once --workspace $AgentWorkspace --policy $MismatchPolicy
"Exit identity mismatch: $LASTEXITCODE"
```

Esperado: invalid_policy e workspace_identity_mismatch, exit 2. Nenhuma live
action. Para tamper e interrupção, usar run de teste isolado e seguir a seção 6
do roteiro: preservar bytes exatos e intent, sem reescrever hashes ou apagar
evidências para liberar replay. Interrupção não deve ser provocada durante o
upload real deste run de aceite.

Auditar todos os journals do novo run localmente, antes de compartilhar:

```powershell
Get-ChildItem (Join-Path $AgentWorkspace "logs/agent") -Filter *.json | ForEach-Object {
    $Expected = ((Get-Content -Raw ($_.FullName + ".sha256")) -split '\s+')[0]
    $Actual = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    [pscustomobject]@{ Journal = $_.Name; SHA256_OK = ($Expected -eq $Actual) }
}
```

Todos devem retornar SHA256_OK=true. Revisar conteúdo quanto a senhas, locators,
private key, caminhos de transporte e mensagens brutas antes de enviar journals
e sidecars. Não anexar profiles, variáveis de ambiente ou material privado PKI.

## Alterações documentais desta revisão

Registro de gates por captura; status/roadmap atualizados para aceite parcial;
lock Windows com arquivo .py e variáveis explícitas em cada janela; validação
de entrada vazia do escopo; comandos de upload com verificação dos paths PKI.
Nenhuma mudança no motor/agente, nos grants do LAB ou na versão executável.
