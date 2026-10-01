# Cancã — Optional Agent v0.5f.0 / evidências P01LAB R1

Revisão: 01/10/2026. **CANDIDATE — validação Windows parcial.**
Implementação: PR #84, main `b85746a38295def054a3822fb152086fae9ef3b2`.
Fonte: 22 capturas fornecidas pelo operador (17 iniciais + 5 de upload); resultados observados, sem execução
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
| 221101 | Upload do P01LAB-AGENT-R1 advanced com inputs mTLS; próxima chamada sem inputs already_complete; runtime state_integrity=true. Paths PKI verificados sem erro. |
| 221111 | Novo run: FULL actions_total=5, completed=5, collected=5, authentication_successes=5, failures=0 e open_credential_circuits=0. Resolver 5 Network + 5 FULL -> 5 logical, zero unresolved/ambiguous/conflicts. Bundle input_count=8. |
| 221128 | Upload completed, attempts=1, HTTP 201/imported, semantic_match=true, authenticated_node_id=P01-MGMT01, mTLS e verificação TLS true; automatic_retry_of_completed_step=false. |
| 221139 | Oito referências do novo run, incluindo upload_receipt: exists=true e sha256_match=true; next_action=complete. |
| 221147 | Status declara plaintext_credentials_persisted=false, private_key_material_persisted=false e secret_provider_references_persisted=false; zero_input_upload_resume_supported=true. Não substitui auditoria do conteúdo dos journals. |

Journals da prova no run concluído: `49adc374-0001-45e2-bdd3-39bc55befe93`
e `702c2071-9bb9-41eb-ac8d-e99e325c6232`. Os hashes foram exibidos como válidos;
os arquivos originais não foram recebidos nesta revisão.

Novo run: upload journal `1e7706e8-b97d-47f2-9e83-d18366802ea3`; repeat journal
`b8afc164-7649-449f-ae0f-0134f06e1280`.
Receipt observado: `P01-Upload-Receipt_bnd-62a74d08048b75988a23.json`.
Seu sidecar corresponde conforme runtime status. Não foi recebido o JSON original.

## Decisão de aceite

| Gate | Situação |
|---|---|
| Doctor/status e policy válida | Comprovados no Windows |
| Resume do run concluído | Comprovado no cliente; state inalterado e dois hashes válidos; confirmação de nenhum POST nos logs do servidor pendente |
| Default-deny e grants separados | Discovery/AUTH/FULL/upload negados nos respectivos checkpoints |
| Progressão unitária | Comprovada de discovery até upload |
| FULL real no novo run | Comprovado: 5/5 completed/collected, 5 auth successes, 0 failures/circuits |
| Resolver real no novo run | Comprovado: 5 logical, zero unresolved/ambiguous/conflicts |
| Lock agente e portátil | Comprovado com bloqueio e liberação; não comprova encerramento abrupto do processo |
| Ausência de serviço/agendamento | Comprovada pelos flags do doctor |
| Upload mTLS do agente | Comprovado no novo run: HTTP 201/imported, semantic_match=true, mTLS/TLS true e receipt íntegro |
| Repeat sem inputs de transporte | Comprovado no cliente: already_complete e attempts=1; confirmação independente de nenhum segundo POST nos logs do servidor pendente |
| Journals do novo run íntegros/sanitizados | Pendente; dois hashes do run antigo não cobrem o novo run inteiro |
| Policy inválida / identidade divergente / tamper | Pendentes de evidência real |
| Interrupção com intent running / review_required | Pendente de evidência real em run isolado |
| Linux real | Não executado nesta rodada; CI Ubuntu passou |

Retém CANDIDATE. Não inicia instalação do Windows Service v0.5f.1 até o fechamento
do aceite definido no roteiro. O novo run tem resultado FULL 5/5 próprio,
distinto do resultado 4/4 do run portátil anterior.

## Gate concluído: upload mTLS do P01LAB-AGENT-R1

Upload e repeat concluídos nas capturas 221101–221147. Os comandos abaixo ficam
como referência da prova executada. Não repetir discovery/AUTH/FULL/export,
reinicializar o workspace ou usar force-resend para esta prova.
O próximo trabalho é o bloco de negativos/journals, não outro upload.

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

As capturas mostram timestamps de journal em `2026-10-02T00:06...Z`,
`00:15...Z` e `01:10...Z`, enquanto os nomes são de 01/10 às 21h/22h. Conferir data/fuso e
sincronização do node, sem concluir a causa apenas pelos nomes de arquivo:

```powershell
Get-Date
(Get-Date).ToUniversalTime()
Get-TimeZone
w32tm /query /status
```

## Fechamento dos negativos e journals

Este é o próximo bloco. O run P01LAB-AGENT-R1 já está completo.
Na janela PowerShell com a .venv ativa, definir os caminhos antes dos comandos:

```powershell
$AgentWorkspace = "C:\Canca\runs\P01LAB-CTX-R1\P01LAB-AGENT-R1"
$AgentPolicy = Join-Path $AgentWorkspace "config/agent-policy.json"
```

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

Registro das 22 capturas, incluindo upload/receipt e FULL 5/5;
status/roadmap atualizados para aceite parcial;
lock Windows com arquivo .py e variáveis explícitas em cada janela; validação
de entrada vazia do escopo; comandos de upload com verificação dos paths PKI.
Nenhuma mudança no motor/agente, nos grants do LAB ou na versão executável.
