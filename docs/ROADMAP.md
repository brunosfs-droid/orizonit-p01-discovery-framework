# Cancã — Engineering Roadmap

> Cancã is Orizon IT Product 01 (P01). Existing P01 identifiers remain valid during Technical Alpha for compatibility.

## Roadmap vigente — rebaseline 06/10/2026 (-03)

[Especificação 1.0](PRODUCT_SPEC_1.0.md) · [ADR 0036](ADR_0036_Workspace_First_1.0.md) ·
[Backlog](BACKLOG_1.0.md) · [Implementação/migração](IMPLEMENTATION_PLAN_1.0.md) ·
[Testes/EVE-NG](TEST_PLAN_1.0.md).

Baseline atual: v0.6.27 CANDIDATE opt-in schema8, contratos Web v0.6.20 e
SNMP v0.4b.9 CANDIDATE. Alpha aberta.
Inventário/Mapper/serviços/dependências passam a integrar a 1.0. Histórico abaixo
preserva entregas e limites anteriores; não é autorização para repetir testes.

| Fase | Prioridade/entrega | Gate |
|---|---|---|
| v0.6.x — Alpha Closure estendida | R01–R06: Workspace/Site/Environment, carga única, observações/identidade/relações/reconciliação/migração | Isolamento, replay, crash, grants e recovery PG16/17/LAB isolado. |
| v0.7 — Environment Experience | R07–R09/R18 base: UI/objetos/wizard/Mapper manual/zoom/submaps/passivos/serviços | UX/ownership/subgrafos/capacidade, feedback controlado. |
| v0.8 — Infrastructure Intelligence | Rede/AD/Compute/virtualização/regras/impacto e fundação catálogo | Vendors/contraprovas/coverage, inferência explícita. |
| v0.8.x — Extensions / Community Beta | Graph/M365/catálogos/MIBs/ícones/firmware/equipamentos selecionados | Suporte qualificado, instalação/CLA/security/SBOM/limites Community. |
| v0.9 — Reporting / GA Candidate | Dashboard/custom reports/actions/changes, backup/restore/hardening | Feature freeze, upgrade/recovery, feedback Design Partners e zero blockers RC. |
| v1.0 GA — Community primeiro | Instalação/compatibilidade/UX/documentação/matriz oficial | Gates afetados aprovados e limitações publicadas. |

Design Partner Alpha é maturidade/feedback controlado sobre entregas v0.7/v0.8,
não substitui requisitos. Community Beta e RC dependem de gates; número da versão
não declara maturidade. Banco de grafos/NMS/remediação não são pré-requisitos.

Primeiro incremento [v0.6.21 CANDIDATE](WORKSPACE_FOUNDATION_v0.6.21.md): registry,
sites/ambientes/grants SQL/RLS/mapping aditivo opt-in.
[v0.6.22](WORKSPACE_COORDINATOR_v0.6.22.md) implementa o coordenador de carga única.
[v0.6.25](WORKSPACE_MODEL_v0.6.25.md), PR #135, entrega o backend dos alvos23–25:
histórico/identidade, grafo manual e reconciliação com jobs/commits cercados.
[v0.6.26](WORKSPACE_API_v0.6.26.md), PR #136, integra a API humana workspace;
[v0.6.27](WORKSPACE_RECOVERY_v0.6.27.md), PR #137, qualifica lease por banco e
recovery isolado. CI da baseline integrada: oito runs/21 jobs PASS.
[Retomada e marcos verificados](validation/WORKSPACE_TASK_RESUMPTION_2026-10-07.md).
Próximo: backfill revisado, readers/reports por revisão e audit HTTP workspace.
UI/Mapper v0.7 segue após os gates R01–R06; jobs/scanners legados, outras
categorias observadas e qualificação operacional ainda exigem seus adapters/gates.
Versões seguintes são alvos de planejamento, não releases.
Estimativas anteriores são hipóteses; reestimar após primeiro incremento/adapters.
Datas não serão prometidas com base somente nesta revisão.

## Histórico de engenharia e componentes

## v0.4a — Network Discovery MVP

- múltiplos CIDRs/faixas;
- exclusões;
- guardrail para scopes grandes;
- ICMP + ARP local + TCP connect;
- reverse DNS;
- banners básicos;
- HTTP/HTTPS fingerprint;
- SSDP/UPnP;
- device/OS guess com confidence;
- JSON + SHA256;
- zero credenciais.

## v0.4b — Credentialed Enrichment

### v0.4b.1 — Credential Manager Foundation
- Credential Profile sem segredo em arquivo;
- Secret Provider abstraction;
- prioridade e escopo por credencial;
- tentativas limitadas e lockout protection;
- nenhum segredo em JSON/log.
- **Status:** LAB VALIDATED no Windows.

### v0.4b.2 — SSH Enrichment
- password auth usando Secret Provider;
- TOFU/strict host key policy;
- allowlist fixa de comandos read-only;
- hostname/kernel/platform;
- interfaces, routes e IPv4 forwarding;
- candidate networks sem scan automático;
- JSON + SHA256.
- **Status:** autenticação real validada contra Dropbear; o equipamento de teste aceitou SSH, mas não devolveu output no canal exec. v0.4b.2.1 passa a classificar explicitamente esse caso como `authenticated_no_exec_output`. Coleta completa foi validada em Ubuntu e Rocky através do P01-MGMT01, com hostname, OS/kernel, interfaces, rotas, IPv4 forwarding e candidate networks. **Status: LAB VALIDATED para Linux controlado.**

### v0.4b.3 — Context-aware Credentialed Discovery
- combinar protocolo + scope + serviço detectado + fingerprint/device class;
- selectors opcionais de OS family, device type, hostname/vendor e realm;
- perfis Windows domain e Windows local separados;
- `failure_budget_per_job` declarado por profile para futura proteção de credenciais compartilhadas;
- nunca tentar credencial somente porque um IP foi descoberto;
- planner seguro que consome o JSON do Network Discovery e produz um plano sem resolver secrets;
- orquestração por ativo com stop-after-success nas próximas integrações;
- primeira validação corporativa no Discovery Node P01-MGMT01.
- **Status:** v0.4b.3.1 LAB VALIDATED. O Windows 11 validou três gates: (1) sem WinRM -> `not_planned`; (2) WinRM disponível + sem profile -> `not_planned`; (3) WinRM + profile workstation/domain compatível -> `adapter_candidate`, ainda sem resolver secret. Circuit breaker permanece pendente do executor multi-target.

### v0.4b.4 — WinRM Credentialed Enrichment
- WinRM HTTP/HTTPS;
- password + NTLM na primeira iteração;
- Context-aware Credential Profiles;
- PowerShell/CIM read-only;
- identity/domain/OS/network/firewall/hotfixes;
- candidate networks sem auto-scan;
- JSON + SHA256 sem secrets.
- **Status:** AUTH/NTLM validado no P01-MGMT01. A coleta full v0.4b.4 encontrou o limite `The command line is too long.`.

### v0.4b.4.1 / v0.4b.4.2 — Modular WinRM Collection
- divide a coleta em seções PowerShell pequenas e independentes;
- preserva seções bem-sucedidas em falhas parciais;
- compatibilidade Windows PowerShell 5.1;
- filtra /32 locais de candidate networks;
- registra `collection_sections` e `failed_section_count`;
- mantém candidate networks sem auto-scan.
- **Status:** LAB VALIDATED no P01-MGMT01 e no P01-DC01, incluindo profile local e profile de domínio.

### v0.4b.4.3 — WinRM Failure Semantics
- separar falha de transporte de credencial inválida;
- não consumir failure budget de credencial em ConnectTimeout/ConnectionError;
- preparar o executor multi-target e circuit breaker.
- **Status:** runtime validated. O comportamento foi exercitado em Domain Controller e workstation de domínio; falhas de transporte não são interpretadas como credencial inválida.

### v0.4b.5 — Multi-target Credentialed Executor
- consumir somente targets/protocolos marcados `adapter_candidate`;
- revalidar profile/context antes de resolver secret;
- dispatch controlado para SSH e WinRM;
- concorrência conservadora e determinística;
- shared-credential circuit breaker por job;
- apenas `failure_category=authentication` consome failure budget;
- `transport` não penaliza credential health;
- evidência agregada por job + referências por target;
- dry-run obrigatório no primeiro LAB.
- **Status:** LAB VALIDATED em dry-run, AUTH-only e FULL nos cinco ativos do P01LAB.

### v0.4b.6 — Assessment Context & Credential Intake
- Assessment Manifest persistente e não secreto;
- domínios/realms declarados como hints, nunca como prova;
- estados de evidência `declared`, `observed` e futuro `credentialed_confirmed`;
- taxonomy independente para `realm_kind`, `target_classes`, `privilege_class`, `purposes` e protocolo;
- intake wizard grava profile metadata + Secret Provider reference, nunca a senha;
- perfis high-privilege exigem acknowledgement, failure budget 1 e uma tentativa;
- planner v0.4b.3.2 consome manifest e só promove realm AD para `observed` quando houver evidência compatível;
- conflito entre realm declarado e observado bloqueia planning em vez de escolher silenciosamente;
- rich profiles não podem ser usados sem contexto.
- **Status:** LAB VALIDATED no P01LAB. Positive gate confirmou declared+observed -> adapter_candidate; negative gate confirmou declared-only -> not_planned, sem resolver secret ou autenticar.

### v0.4b.7 — SNMP essencial de alvo único
- Adapter independente CANDIDATE: SNMPv3 authPriv SHA-256/AES-128; SNMPv2c explicitamente escolhido, sem fallback.
- Dry-run sem rede/secret; profile ID único revalidado por scope/protocolo/contexto, execução autorizada explícita.
- GETs numéricos fixos, até oito operações, retries zero, timeout/prazo global; JSON/SHA256 com cobertura por campo e falhas parciais.
- CI loopback com UDP/USM/criptografia reais em Linux/Windows e Python 3.10/3.12/3.13; vendors e operação real permanecem CANDIDATE.
- [Guia](../credentialed_enrichment/README-SNMP.md) · [ADR 0033](ADR_0033_Read_Only_SNMP_v0.4b.7.md).
- Planner/executor recebem extensão explícita v0.4b.8; integração de evidência/portable segue em v0.4b.9.

### v0.4b.8 — planejamento e execução SNMP explícitos
- Até 25 endpoints UDP em seeds existentes, profile ID escolhido, scopes/protocolo autorizado no manifest; serviço declarado não vira UDP observado.
- Binding de profile completo, referências, contexto, endpoint e autorização; revalidação antes de secrets e no dispatch.
- Executor opt-in `--enable-snmp`, default off no portable; AUTH/FULL reutilizam adapter v0.4b.7 sem alterar os GETs.
- Leitura não confirmada suspende referências compartilhadas, sem declarar falha de senha; perfis independentes continuam.
- JSON/SHA256 exclusivos e privados; agentes loopback reais em matriz Linux/Windows/Python, sem novo teste de LAB.
- [Contrato](SNMP_PLANNED_EXECUTION_v0.4b.8.md) · [ADR 0034](ADR_0034_Planned_SNMP_Execution_v0.4b.8.md). Operação/vendores permanecem CANDIDATE.

### v0.4b.9 — evidência SNMP e portable gerenciado
- Reader puro valida envelopes standalone/target, OIDs, tipos, limites, estados e cobertura; sem provider/runtime SNMP no replay.
- Resolver v0.4c.1 conserva claims observados e fontes; sysObjectID não é identidade forte, sysName exige corroboration e não promove realm AD.
- AUTH/dry/falhas ficam em diagnósticos; FULL parcial conserva cobertura; uptime variável não gera conflito de configuração.
- Bundle v0.5a.1 mantém bytes/formato e valida SNMP; importer v0.5b.1 compara campos/fontes/cobertura/correlação no replay.
- Portable v0.5e.7 recebe requests explícitos, congela hashes e exige enable-snmp em prévia/AUTH/FULL; diretórios privados novos e resume sem rede.
- Collector sem login Cancã; defaults do agent/scheduler preservados. Operação real CANDIDATE, CI sintético separado de LAB.
- [Contrato](SNMP_EVIDENCE_PORTABLE_v0.4b.9.md) · [ADR 0035](ADR_0035_SNMP_Evidence_and_Portable_v0.4b.9.md).

### v0.4b.10+ — próximos adapters e integrações
- Kerberos/HTTPS/certificate para WinRM;
- WMI/DCOM fallback quando necessário;
- auditoria de autenticação multi-protocolo.

## v0.4c — Asset Resolver

### v0.4c.0 — Offline correlation foundation
- consumir Network Discovery + target results FULL de WinRM/SSH + Assessment Manifest opcional;
- nunca auto-merge por IP isolado;
- strong identifier exato ou namespace + network corroboration para auto-merge;
- Network Discovery observations permanecem seeds independentes;
- provenance por campo;
- conflitos explícitos sem silent overwrite;
- realm `observed` separado de `credentialed_confirmed`;
- output determinístico JSON + SHA256;
- zero network access, authentication ou secret resolution.
- **Status:** LAB VALIDATED. O P01LAB real resolveu 5 Network Discovery assets + 5 FULL observations em 5 logical assets, 0 unresolved, 0 ambiguous e 0 conflicts. O realm de autenticação foi separado da identidade de diretório.

### v0.4c.1 — evidência SNMP observada
- Integração do contrato SNMP v0.4b.9, preservando schema 0.4c e semântica legada.
- sysName remoto observado + evidência independente; sysObjectID somente modelo.
- Proveniência por OID/SHA e cobertura por fonte; nenhuma inferência de associação AD.

### Próximas iterações v0.4c
- AD computer object / objectGUID / SID;
- system UUID / SMBIOS UUID / service tag;
- Windows Collector e Linux Collector locais;
- registry persistente de asset IDs entre assessment runs;
- identificação SNMP ampliada e VMware identifiers futuramente.

Objetivo: um ativo lógico, múltiplas fontes de evidência, sem duplicidade no relatório.

## v0.4d — Dynamic Scope Expansion

Usar evidências de interfaces, rotas, VLANs e neighbors obtidas pela v0.4b para descobrir novas redes candidatas e expandir o discovery somente dentro de limites explicitamente autorizados.

Guardrails:
- auto-expansão desligada por padrão;
- authorized_supernets + exclude_scopes;
- max_depth / max_new_networks / max_hosts;
- deduplicação de redes já visitadas;
- sem pivot/jump automático;
- sem herança automática de credenciais;
- redes sem alcance ficam registradas para futuro Remote Discovery Node/Sensor.

## Discovery Nodes / Sensors

O P01 deve suportar múltiplos Discovery Nodes em segmentos distintos. Um node escaneia apenas redes alcançáveis a partir dele e envia evidências para consolidação posterior. Não usar ativos arbitrários como pivots.

O LAB inicial usará P01-MGMT01 como Discovery Node por possuir acesso ao segmento NAT e ao segmento interno do laboratório.

## Depois da v0.4

- Reporting Engine v0.1;
- SNMP/LLDP/CDP e topologia ampliada;
- plugins de fabricantes/controladoras;
- remote discovery nodes/sensors;
- CVE correlation e Patch Compliance.


## v0.5 — Discovery Node / Evidence Bundle / Central Ingestion

### v0.5a — Evidence Bundle Format
- formato portátil único para connected upload e offline/manual import;
- bundle manifest + evidence inventory + SHA256;
- preservar assessment/run/node identity e component/schema versions;
- no secret values or Secret Provider references;
- formato transportável como `.p01bundle`.
- **Status:** LAB VALIDATED no P01LAB. P01LAB-BUNDLE-R1 empacotou 8 artifacts, validou 9 inventory entries, outer SHA256, zero secret material e transport mode agnostic.

### v0.5b — Offline Export / Import
- validar o bundle antes de materializar qualquer payload;
- preservar o `.p01bundle` original como raw evidence;
- safe materialization sem `extractall`;
- import idempotente por bundle ID + SHA256;
- receipt JSON + SHA256;
- reexecutar Asset Resolver usando somente evidências importadas;
- comparar semanticamente resultado server-side com o Asset Resolver edge embarcado;
- segunda importação do mesmo bundle retorna `already_imported`.
- **Status:** LAB VALIDATED. P01LAB-BUNDLE-R1 foi importado em store limpo; server-side Asset Resolver reproduziu 5 logical assets, 0 unresolved, 0 ambiguous, 0 conflicts, semantic_match=true; segunda importação retornou already_imported; receipt JSON/SHA256 validado.

### v0.5c — Central Ingestion API
- localhost-only HTTP ingestion foundation;
- mesmo `import_bundle()` da v0.5b;
- mandatory Content-Length + X-P01-Bundle-SHA256;
- idempotency key;
- upload-size guard;
- staging before validation/import;
- GET status + health endpoint;
- non-loopback bind rejected.
- **Status:** LAB VALIDATED. Positive path, idempotência, status lookup, semantic equivalence, bind loopback-only, negative gates 400/422/422/413 e connection hygiene v0.5c.1 foram validados no P01LAB.

### v0.5d — Connected Discovery Node Upload
- upload outbound-only do Discovery Node para o servidor;
- HTTPS com TLS 1.2+;
- mTLS na primeira iteração;
- server certificate validation no Node;
- client certificate validation no servidor;
- `X-P01-Node-ID` ligado à identidade DNS SAN/CN do certificado cliente;
- bundle `node_id` deve coincidir com o node autenticado;
- status lookup escopado ao node autenticado;
- retries limitados apenas a falhas de transporte;
- nenhum retry automático de 4xx/TLS-auth failures;
- no server-initiated arbitrary execution.
- **Status:** LAB VALIDATED. Local R1 validou trust/mTLS/Node-ID/spoof/untrusted-client/idempotência. Separate-host R2 validou P01-MGMT01 (192.168.100.20) -> P01-LNX-RKY01 (192.168.100.50), FQDN server validation, semantic_match=true e cross-host idempotency.

### v0.5e.0 — Portable Discovery Node Runtime Foundation
- portable-first Windows/Linux runtime;
- `doctor`, `init`, `status`, `export` e `upload`;
- workspace isolado por assessment/run;
- state/config JSON + SHA256;
- checkpoints determinísticos e auditáveis;
- Evidence Bundle v0.5a e uploader mTLS v0.5d reutilizados sem pipeline paralelo;
- completed bundle/upload não são repetidos silenciosamente;
- private-key path é invocation-only e não entra no state;
- Network Discovery/Planner/Executor/Asset Resolver permanecem `external_required` nesta primeira versão.
- **Status:** CANDIDATE em CI. Issue #60.

### v0.5e.1 — Unified Discovery Orchestration
- incorporar Network Discovery -> Planner -> Executor -> Asset Resolver à mesma state machine;
- explicit authorized-scan acknowledgement;
- safe resume sem repetir autenticações concluídas;
- artifacts/hashes propagados entre etapas;
- `run` como fluxo operacional principal.
- **Status:** planned após LAB v0.5e.0.

### v0.5f — Optional Installed Service/Agent
- reuse the same portable runtime core;
- add service lifecycle, scheduling and unattended execution policy.
- **v0.5f.0:** LAB VALIDATED (Windows P01LAB R1; Linux CI) — cross-platform agent doctor/status/run-once,
  strict versioned default-deny policy, independent stage grants, shared OS lock,
  checkpoint integrity and sanitized JSON/SHA256 journal. No service installation.
  Windows R1 partial evidence: completed-resume, progression through upload,
  FULL 5/5, separate grants, shared lock and real agent mTLS receipt passed.
  Repeat returned already_complete with attempts=1; invalid policy and identity
  mismatch rejected with exit 2. Config tamper and pre-dispatch process exit
  passed in an isolated Windows run: review_required twice, no replay, restored
  policy, preserved intent and released lock. Journal hashes/contract passed
  17/17 in the complete run and 4/4 in the negative run. Isolated artifact/target
  tamper passed with 75 unchanged source files; active API console shows no POST
  after client repeats in the observed process/window; 27 captures reviewed;
  [evidence record](validation/OPTIONAL_AGENT_P01LAB_R1_v0.5f.0.md).
- **v0.5f.1:** LAB VALIDATED (Windows Server 2022 P01LAB R1 manual lifecycle) — Windows SCM host, LocalService/service SID, manual
  start, one invocation per start, cooperative stop/remove, no automatic recovery
  or scheduling. Canonical journals/review gate preserved after restart.
  [Service evidence](validation/WINDOWS_SERVICE_P01LAB_R1_v0.5f.1.md): 4 starts,
  2 denials/2 reviews, state/intent preserved, lock reacquired, removed service,
  7/7 journal audit. No live service-account AUTH/FULL/upload or soak claim.
- **v0.5f.2:** LAB VALIDATED (Rocky 10.2 P01LAB R1 manual lifecycle) — Linux/systemd manual lifecycle, dedicated account,
  exact unit checks, one invocation/start, cooperative stop, preserved review gate,
  no automatic recovery/timer. Native Ubuntu CI passed.
  [Rocky R1 evidence](validation/LINUX_SERVICE_P01LAB_R1_v0.5f.2.md): Python
  3.12.13/systemd 257, SELinux Enforcing at preflight, PASS/exit 0, four starts,
  two denials/two reviews, preserved state/intent, released lock, removed unit,
  seven audited journals, retained fixture and corroborating systemd journal.
- **v0.5f.3:** R1 offline LAB VALIDATED em Windows/Rocky; soak estendido pendente. Scheduling explícito e limitado, sem replay ou recovery automático.
  Gates: explicit default-off scheduling; reread identity/policy/integrity at each
  tick; shared lock with no overlapping dispatch; halt on failure/running intent
  until operator reconciliation; never auto-replay AUTH/FULL/POST; cooperative
  stop and preserved evidence across host restart; bounded offline soak with
  journal/sidecar audit, restart counts and zero unexpected live access. Native
  Windows/Linux CI precedes separate real LAB rounds. Current hosts retain manual
  start and no automatic recovery until that candidate is implemented/tested.
- Issue #83; [agent guide](../agent/README.md) and
  [LAB gate](LAB_OPTIONAL_AGENT_v0.5f.0_R1.md).


### v0.5e.1 — Managed Network Discovery
- Portable runtime `run` command controls Network Discovery;
- explicit authorized-scan acknowledgement;
- effective IPv4 scope constrained by Assessment Manifest `authorized_scopes`;
- manifest excludes automatically applied;
- output JSON/SHA256 stored under the run workspace;
- repeat run returns `already_complete` without a second scan;
- force-rescan blocked when downstream completed artifacts would become stale.
- **Status:** LAB VALIDATED no P01LAB. Ack obrigatório, rejeição de escopo não autorizado, execução autorizada em `192.168.100.0/24`, JSON/SHA256 no workspace e resume sem segundo scan foram confirmados.

### v0.5e.2 — Managed Credential Planner
- segundo `run` avança do Network Discovery concluído para o Credential Planner;
- usa somente o artifact/hash do Network Discovery registrado no workspace;
- consome Assessment Manifest + Credential Profiles referenciados no `init`;
- gera Credential Plan JSON/SHA256 dentro do workspace;
- zero network activity, zero secret resolution e zero authentication;
- workspaces v0.5e.1 com `credential_plan: external_required` podem ser continuados in-place;
- repeat plan retorna `already_complete`;
- force-replan é bloqueado quando invalidaria etapas downstream concluídas.
- **Status:** LAB VALIDATED no P01LAB-RUNTIME-R2. 4 assets, JSON/SHA256 gerados, zero network/secret/auth e resume `already_complete` confirmados.

### v0.5e.3 — Managed Credentialed Executor Dry-run
- terceiro `run` avança para o Multi-target Credentialed Executor;
- plan artifact/hash e live Credential Profiles são revalidados;
- execução limitada a `dry_run` nesta iteração;
- Credentialed Job JSON/SHA256 é gravado no workspace;
- checkpoint `preview_completed` não é confundido com autenticação real concluída;
- zero secret resolution e zero authentication attempts;
- repeat dry-run retorna `already_complete`.
- **Status:** LAB VALIDATED no P01LAB-RUNTIME-R3. 5 assets descobertos, 4 adapter candidates, 4 actions ready, JSON/SHA256 no workspace e resume `already_complete` confirmados.

### v0.5e.3.1 — Managed Credentialed Executor AUTH-only
- continua o workspace `preview_completed` sem refazer discovery/planning;
- live execution exige `--execute --auth-only --ack-authorized-access`;
- Credential Plan, dry-run preview e Credential Profiles são revalidados antes de autenticar;
- executor existente permanece sequencial (`concurrency=1`) e preserva failure budget/circuit breaker;
- AUTH evidence por target + aggregate job permanece JSON/SHA256;
- checkpoint `auth_validated` não é confundido com FULL enrichment;
- repeat AUTH-only retorna `already_complete` sem nova autenticação;
- falha/parcial exige retry explícito com `--force-auth-retry`.
- **Status:** LAB VALIDATED no P01LAB-RUNTIME-R3. Gate sem acknowledgement bloqueado; 4/4 actions autenticadas com sucesso; 0 falhas; 0 circuits; JSON/SHA256 por target e resume sem segunda autenticação confirmados.

### v0.5e.3.2 — Managed Credentialed Executor FULL enrichment
- continua o workspace `auth_validated` sem repetir discovery/planning/dry-run/AUTH;
- FULL exige `--execute --full-enrichment --ack-authorized-access`;
- plan, preview, AUTH job e Credential Profiles são revalidados antes da coleta;
- usa o executor v0.4b.5 com `execute=true`, `auth_only=false`, `concurrency=1`;
- per-target FULL evidence + aggregate job permanecem JSON/SHA256;
- partial/failure preserva evidência e exige `--force-full-retry`;
- repeat FULL retorna `already_complete` sem novo acesso/autenticação;
- checkpoint final da etapa: `credentialed_execution: full_completed`.
- **Status:** LAB VALIDATED no P01LAB-RUNTIME-R3. Gate sem acknowledgement bloqueado; 4/4 actions completed/collected, 4 auth successes, 0 failures/circuits, FULL JSON/SHA256 por target e resume sem segunda coleta confirmados.

### v0.5e.4 — Managed Asset Resolver
- continua o workspace `full_completed` sem repetir etapas live;
- consome o Network Discovery registrado no state e somente os target JSON referenciados pelo EXEC-FULL;
- rejeita target evidence fora do workspace ou com sidecar/hash inválido;
- AUTH-only evidence não é misturado ao conjunto de correlação;
- executa o Asset Resolver v0.4c.0 offline/read-only;
- grava JSON/SHA256 em `resolved`;
- checkpoint `asset_resolver: completed` inclui contagens e bindings dos inputs;
- repeat resolver retorna `already_complete`;
- `--force-reresolve` é bloqueado se Bundle/Upload já estiverem concluídos.
- **Status:** LAB VALIDATED no P01LAB-RUNTIME-R3. 5 Network assets + 4 EXEC-FULL observations -> 5 logical assets, 0 unresolved, 0 ambiguous, 0 conflicts; JSON/SHA256 e resume `already_complete` confirmados.

### v0.5e.5 — Workspace-driven Evidence Bundle
- `export --workspace <path>` não exige paths de Network/evidence/resolver;
- deriva inputs somente dos artifacts/checkpoints validados no state;
- usa somente targets explicitamente referenciados pelo EXEC-FULL;
- valida Network, FULL job, FULL targets e Asset Resolver por SHA256/sidecar;
- preserva export explícito/manual para compatibilidade;
- grava `selection_mode=workspace_state` e bindings exatos dos inputs;
- repeat export retorna `already_complete` sem reconstrução.
- **Status:** LAB VALIDATED no P01LAB-RUNTIME-R3. Bundle workspace_state com 7 payload artifacts, 4 credentialed EXEC-FULL, validate=true, inventory=8, outer SHA256=true e repeat export sem rebuild.

### v0.5e.6 — End-to-end Connected Upload / zero-input resume
- primeiro upload usa o uploader mTLS v0.5d e exige URL/CA/client cert/client key explícitos;
- private-key path continua invocation-only e não entra no state;
- após upload completed, `upload --workspace <path>` retorna `already_complete` sem exigir parâmetros de transporte;
- resume completed ocorre antes de setup de TLS/rede;
- `--force-resend` exige novamente todos os parâmetros de transporte;
- receipt JSON/SHA256 e state transition para `upload: completed` permanecem.
- **Status:** LAB VALIDATED no P01LAB-RUNTIME-R3. Upload mTLS HTTP 201/imported, semantic_match=true, node P01-MGMT01, receipt JSON/SHA256, state `upload: completed`, `Next action: complete`, zero-input repeat `already_complete` sem novo POST e force-resend sem transporte bloqueado.

### v0.5e.7 — SNMP gerenciado explícito
- Requests no planejamento; hashes de request/manifest/profiles verificados antes de prévia/acesso.
- enable-snmp obrigatório em cada estágio; AUTH validado antes de FULL; nenhuma ativação pelo scheduler.
- FULL SNMP parcial com acesso confirmado permite resolver/export com cobertura explícita.
- Tentativas privadas novas, preservação de retry e conclusão sem repetir rede; nenhum login Cancã.
- [Contrato e limites](SNMP_EVIDENCE_PORTABLE_v0.4b.9.md). Vendors/LAB permanecem CANDIDATE.

Follow-up: v0.5f Optional Installed Service/Agent e gates de product alpha/persistência central mantêm seu fluxo independente.


### v0.5f.3 — Explicit bounded service scheduling (LAB VALIDATED for bounded offline soak)
- Shared scheduler around canonical run_once; default off, operator opt-in after installation.
- Fixed delay 60..86400s after completion, bounded attempts, policy reread and native workspace lock.
- Running/halted session journal blocks restart and manual-mode bypass until reviewed.
- OS start remains manual with no recovery/retry/timer; stop wakes wait cooperatively.
- Native scheduled R1 uses real 60s spacing and interrupted-wait review on SCM/systemd.
- [Status](STATUS_SCHEDULER_v0.5f.3.md), [ADR 0010](ADR_0010_Scheduler_v0.5f.3.md), [LAB R1](LAB_SCHEDULER_v0.5f.3_R1.md).
- Windows/Rocky short offline R1 passed on 02/10/2026 (-03): PASS/exit 0, real 60s interval, retained interrupted intent and zero replay. [Acceptance](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md).
- Extended offline soak passed on 02/10/2026: 10 real ticks, ~9 minutes per first cycle, 11 journals/3 sessions per host, restart review with zero replay. [Acceptance](validation/SCHEDULER_P01LAB_EXTENDED_v0.5f.3.md).
- Multi-day soak and live service principal qualification remain separate unqualified gates.

### v0.6.0 — PostgreSQL metadata foundation (CANDIDATE)

- Primeiro incremento da Product Alpha, issue #63; R2 distribuído já aprovado.
- Migração e indexação explícita de imports em PostgreSQL 16/17, sem alterar o store ou a API atual.
- Recibo/bundle/identidade verificados antes da conexão; transação atômica, idempotência e conflitos sem overwrite.
- CI de banco real; servidor PostgreSQL no LAB, backup/restore e integração de ingestão ainda pendentes.
- [Status](STATUS_PERSISTENCE_v0.6.0.md), [ADR 0011](ADR_0011_PostgreSQL_Foundation_v0.6.0.md), [guia](../persistence/README.md), [próximos passos e soak](NEXT_STEPS_v0.6.0.md).

### v0.6.1 — Opt-in API indexing and reconciliation (CANDIDATE)

- API `--metadata-index postgres`, default off; filesystem acknowledgment permanece independente do índice.
- Estado de índice explícito no POST/GET, erros fixos, identidade e fonte verificadas antes do banco.
- Reconciliação explícita de um import com `index-import`; sem migração automática, sweep ou retries.
- Testes reais de interrupção após publicação dos arquivos e após commit PostgreSQL, preservando replay idempotente.
- [ADR 0012](ADR_0012_Ingestion_Index_v0.6.1.md), [guia](INGESTION_INDEX_v0.6.1.md), [status](STATUS_INGESTION_INDEX_v0.6.1.md).

### v0.6.2 — Administrative assessment lifecycle (CANDIDATE)

- Estados explícitos e transições administrativas; revisão esperada, request ID idempotente e eventos atômicos.
- Migração 0002 explícita, backfill registered/revisão 0, preservando imports e migração 0001.
- Ingestão não infere conclusão nem reabre estados terminais; nenhuma mudança no runtime/scheduler.
- CI PostgreSQL 16/17 real: upgrade, concorrência, replay, rollback, estados terminais e permissões.
- LAB PostgreSQL de roles/TLS/backup/restore permanece pendente; próxima modelagem independente: identidade persistente de assets.
- [ADR 0013](ADR_0013_Assessment_Lifecycle_v0.6.2.md), [guia](ASSESSMENT_LIFECYCLE_v0.6.2.md), [status](STATUS_ASSESSMENT_LIFECYCLE_v0.6.2.md).

### v0.6.3 — Persistent asset identity per assessment (CANDIDATE)

- ID central próprio, observações por bundle/ordinal e proveniência por artefato/sinal.
- Fonte verificada e replay offline privado do resolver; JSON embutido não decide identidade.
- Associação conservadora: candidato único, duas categorias credentialed e sinal forte; conflitos/ambiguidades exigem revisão.
- Escopo assessment; nenhum merge/relink, correlação entre assessments, conclusão de lifecycle ou alteração da ingestão.
- Migração 0003 explícita; CI PostgreSQL 16/17 real, com upgrade, rollback, replay e concorrência entre bundles.
- LAB PostgreSQL e resolução manual de identidades seguem separados; próxima modelagem independente: findings e sua origem verificável.
- [ADR 0014](ADR_0014_Persistent_Assets_v0.6.3.md), [guia](ASSET_REGISTRY_v0.6.3.md), [status](STATUS_ASSET_REGISTRY_v0.6.3.md).

### v0.6.4 — Source-bound findings and explicit coverage (CANDIDATE)

- Duas regras para enrichment WinRM atual, sem presumir compatibilidade com collectors locais.
- Fonte inventariada, catálogo/engine por hash, resultados de cobertura e ligação conservadora a assets.
- Migração 0004 explícita; ocorrências Open imutáveis e replay, sem auto-close entre runs.
- CI PostgreSQL 16/17 real: fonte/drift, upgrade, rollback, concorrência, roles e paginação.
- Próximo trabalho independente: qualificação do servidor, backup/restore e relatório com cobertura.
- [ADR 0015](ADR_0015_Findings_v0.6.4.md), [guia](FINDINGS_v0.6.4.md), [status](STATUS_FINDINGS_v0.6.4.md).

### v0.6.5 — Consolidated read-only assessment reporting (CANDIDATE)

- Lifecycle, imports pendentes, identidade, cobertura explícita e ocorrências históricas.
- Catálogos originais e referências de evidência; sem latest implícito, auto-close ou conclusão de segurança.
- Snapshot por consulta e paginação com hash de escopo; excesso de limite rejeita o relatório inteiro.
- Sem migração nova, coleta, raw source revalidation, API remota ou UI.
- PostgreSQL 16/17: reader, paginação, escritor concorrente, lifecycle/ingestion changes e limites.
- [ADR 0016](ADR_0016_Assessment_Report_v0.6.5.md), [guia](ASSESSMENT_REPORT_v0.6.5.md), [status](STATUS_ASSESSMENT_REPORT_v0.6.5.md).

## v0.6.6 — recuperação lógica do par banco/store

- Dump/restore real na matriz PostgreSQL 16/17 em fixture CI exclusiva descartável.
- Igualdade das 14 tabelas, relatório, IDs CAS/findings e eventos históricos.
- Hashes de arquivos, revalidação de evidências e replay sem mutação.
- Nenhuma migração nova; roles/grants e recuperação operacional do LAB permanecem pendentes.
- [Guia](BACKUP_RESTORE_v0.6.6.md) · [ADR 0017](ADR_0017_Backup_Restore_v0.6.6.md).

## v0.6.7 — comparação de recuperação no LAB

- R1 básico PostgreSQL/Rocky LAB VALIDATED no escopo sintético; [aceite](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md).
- Helper read-only com hashes de 14 tabelas/arquivos, revalidação de projeções e comparação exata.
- CI integra o helper ao dump/restore real 16/17; roteiro operacional utiliza destino novo.
- Recuperação LAB sintética aprovada por sete capturas em PostgreSQL 16.15; TLS/roles completos, lifecycle e paginação fenced permanecem gates próprios.
- [Roteiro](LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md) · [ADR](ADR_0018_LAB_Recovery_Check_v0.6.7.md).

## v0.6.8 — lifecycle e paginação na base recuperada

- Aceite limitado da recuperação R1 v0.6.7 no Rocky: 14 tabelas/20 arquivos e replay preservado.
- Helper com inspect somente leitura e exercício explícito de quatro transições, prefixo retomável e requests idempotentes.
- Quatro páginas de avaliações/histórico, rejeição de cursores antigos, conflitos e findings Open preservados.
- Somente canca_p01_restore_r1; fontes/12 tabelas comparadas contra snapshot original, sem migração nova.
- Qualificação CI PostgreSQL 16/17 e LAB são gates distintos; próximo produto: exportação consolidada somente leitura.
- [Roteiro](LAB_POSTGRESQL_LIFECYCLE_R1_v0.6.8.md) · [ADR 0019](ADR_0019_LAB_Lifecycle_Pagination_v0.6.8.md).

## v0.6.9 — exportação consolidada somente leitura

- JSON/Markdown completos com hashes, diretório privado e paginação fenced.
- Código integrado; PR #106 mantém URLs persistidas inertes no Markdown.
- PR #107 corrige inventário de instalação para aceitar a pasta criada pelo Git.
- Exportação funcional LAB VALIDATED no R1 Rocky: instalação corrigida, duas saídas, hashes/permissões/contagens PASS nas capturas 014007/014025/014138/014149/014247.
- Apresentação técnica aceita por conteúdo/parsing GFM dos dois anexos Markdown idênticos; sem qualificação de PDF/renderizador específico. Tentativas bloqueadas anteriores são históricas.
- [Aceite e limites](validation/POSTGRESQL_P01LAB_EXPORT_R1_v0.6.9.md).
- [Guia](REPORT_EXPORT_v0.6.9.md) · [LAB](LAB_POSTGRESQL_EXPORT_R1_v0.6.9.md).

## v0.6.10 — autorização de node por assessment (CANDIDATE)

- Política opt-in no servidor mTLS: grant exato de envio e/ou consulta por node/assessment.
- Negações antes de importer/index; node desconhecido bloqueado antes do body.
- Política limitada/imutável, startup validado e restart controlado para revogação.
- Preserva binding mTLS e propriedade do bundle; sem migração ou principal de usuário.
- Próxima fronteira: autenticação/autorização de operadores na API/Web.
- [Guia](NODE_AUTHORIZATION_v0.6.10.md) · [ADR 0022](ADR_0022_Node_Assessment_Authorization_v0.6.10.md).

## Evolução de produto e substituição de escopo

A decisão de 02/10/2026 mantém Apache-2.0, Community primeiro e comercial posterior.
A sequência então post-1.0 de inventário/Mapper/rede/VMware/serviços foi substituída
em 06/10/2026: integra a 1.0 conforme roadmap vigente/ADR 0036. Cotas e alocação
comercial seguem abertas, sem mudança executável. NMS contínuo/simulação permanecem
fora do escopo. [Edições](LICENSING_AND_EDITIONS.md).

## v0.6.11 — operadores locais e API de relatório (R1 LAB VALIDATED)

- Login humano separado do mTLS dos Discovery Nodes; collector portable continua sem login Cancã.
- Política privada, hashes scrypt, sessões opacas limitadas, expiração/logout e throttle.
- Grant exato de leitura antes do banco; consultas canônicas e páginas fenced somente leitura.
- HTTP apenas em loopback; acesso remoto exige TLS. Sem migração, UI, coleta ou alteração do LAB aprovado.
- Próximas telas Web usarão essa fronteira; integração opcional AD/SSO vem depois, com decisão própria.
- [Guia](../server/README.md) · [ADR 0023](ADR_0023_Local_Operator_API_v0.6.11.md) · [R1 curto](LAB_LOCAL_OPERATOR_R1_v0.6.11.md).
- R1 aprovado nas duas capturas de 03/10: pacote isolado e helper PASS; loopback/base sintética, sem qualificar UI/HTTPS remoto/produção. [Aceite](validation/LOCAL_OPERATOR_P01LAB_R1_v0.6.11.md).

## v0.6.12 — primeiras telas Web de operadores (R1 LAB VALIDATED)

- Login local, logout e relatório por ID de assessment sobre o backend v0.6.11 preservado.
- Resumo histórico, cobertura e proveniência; páginas mantêm o mesmo escopo/cursor.
- Sessão somente em memória, texto seguro no DOM, CSP e proteção de origem/Host.
- Sem alteração no banco, collector, credenciais de alvos ou mTLS de upload.
- R1 Windows/Rocky via túnel SSH aprovado; não repetir instalação, Web, backend, restore, lifecycle ou exportação. Qualificação ampliada/produção continua separada.
- [ADR 0024](ADR_0024_Local_Operator_Web_v0.6.12.md) · [R1 Web](LAB_LOCAL_OPERATOR_WEB_R1_v0.6.12.md).
- Quinze capturas de 03/10 demonstram instalação/login/relatório, negação OTHER, logout/login vazio, janela reduzida e dois STOP PASS com 14 tabelas preservadas e contas removidas. [Aceite](validation/LOCAL_OPERATOR_WEB_P01LAB_R1_v0.6.12.md).
- CI recuperado em 03/10: oito runs/sixteen jobs passaram no attempt 2; PR #112 integrado em dcfb654507428f2a4287caed18e4a6b7d5431b8f. Falhas antes das etapas permanecem históricas; pacote aprovado preservado.

## v0.6.13 — download completo na Web (CANDIDATE)

- ZIP em memória com JSON/Markdown completos e hashes, usando o exportador canônico.
- Grant de leitura, sessão e escopo exibido validados; páginas/terminal fenced, sem retry ou gravação no servidor.
- Um export ativo, deadline cooperativo e 32 MiB; navegador confere bytes/escopo/SHA256 e bloqueia respostas tardias após logout.
- CI HTTP/eventos/Chromium e reader PostgreSQL 16/17; gate manual novo apenas download/verificação no túnel existente.
- Nenhuma migração, coleta, alteração do collector ou repetição dos R1 aprovados.
- [Guia](OPERATOR_WEB_EXPORT_v0.6.13.md) · [ADR 0025](ADR_0025_Operator_Web_Report_Export_v0.6.13.md).
- Código 9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871 qualificado em oito runs/16 jobs;
  [registro CI](validation/OPERATOR_WEB_EXPORT_CI_v0.6.13.md). Novo gate manual:
  [download R1](LAB_OPERATOR_WEB_EXPORT_R1_v0.6.13.md), sem repetir testes antigos.

## v0.6.14 — relatório executivo (CANDIDATE)

- CLI local somente leitura, com JSON/Markdown privados e manifesto/SHA256.
- Cobertura, pendências, identidade e severidades das ocorrências históricas.
- Recomendações agrupadas pela regra/catálogo/engine salvos, com referências completas.
- Sem score de risco, fechamento implícito de findings, migração ou acesso ao store.
- CI sintético e PostgreSQL 16/17 independentes do LAB; validações manuais adiadas
  pelo mantenedor em 03/10. Preserva os onze arquivos do pacote Web v0.6.13.
- [Guia](EXECUTIVE_REPORT_v0.6.14.md) · [ADR 0026](ADR_0026_Executive_Report_v0.6.14.md) ·
  [Registro CI](validation/EXECUTIVE_REPORT_CI_v0.6.14.md).

## v0.6.15 — download executivo na Web (CANDIDATE)

- Botão próprio e endpoint autorizado pelo grant de leitura do assessment exibido.
- Síntese v0.6.14 preservada; ZIP executivo com JSON/Markdown, manifesto e hashes.
- Técnico e executivo compartilham um slot/deadline; formato técnico 0.6.9/0.6.13 preservado.
- Sessões/escopo/limites verificados; sem escrita SQL, saída em disco no servidor ou acesso ao store.
- HTTP/eventos, PostgreSQL SELECT-only e Chromium desktop/mobile verificam os dois tipos.
- Gates operacionais adiados; os pacotes históricos continuam nos pins qualificados.
- [Guia](OPERATOR_WEB_EXECUTIVE_v0.6.15.md) · [ADR 0027](ADR_0027_Operator_Web_Executive_Export_v0.6.15.md) ·
  [Registro CI](validation/OPERATOR_WEB_EXECUTIVE_CI_v0.6.15.md).

## v0.6.16 — seleção de assessments permitidos (CANDIDATE)

- Lista somente os grants da sessão local, sem verificar existência em PostgreSQL.
- Seletor preenche o formulário; consultar permanece explícito e autorizado por ID.
- Limites de 128 IDs/32 KiB, opções como texto, expiração/logout e descarte de respostas tardias.
- Atualização/fallback manual; isolamento entre contas e relatório anterior limpo na seleção.
- Auth/HTTP/eventos, PostgreSQL 16/17 e Chromium desktop/mobile; LAB adiado.
- API standalone e formatos de download preservados; pacotes históricos ficam nos pins.
- [Contrato](OPERATOR_ASSESSMENT_SELECTION_v0.6.16.md) · [ADR 0028](ADR_0028_Operator_Assessment_Selection_v0.6.16.md) ·
  [Registro CI](validation/OPERATOR_ASSESSMENT_SELECTION_CI_v0.6.16.md).

## v0.6.17 — resumo executivo na Web (CANDIDATE)

- A — MVP: consulta explícita de cobertura completa, severidades registradas e recomendações na interface.
- Síntese executiva v0.6.14 preservada; dez grupos por página, regra/catalog/engine históricos e nenhuma referência de ocorrência/evidência no painel.
- Scope fence obrigatório em todas as páginas canônicas, incluindo terminal vazia; um slot compartilhado com ambos os ZIP, deadline cooperativo e JSON limitado a 1 MiB.
- Renderização somente texto, paginação independente da técnica e limpeza/aborto em logout/expiração; sem persistência de token.
- HTTP/eventos, reader PostgreSQL 16/17 e Chromium desktop/mobile; gates manuais adiados, sem ação no LAB hoje.
- Sem migração, SQL de escrita, store, AD/SSO, collector login, inventário ou mapper. Diretório e formatos ZIP anteriores preservados.
- [Contrato](OPERATOR_WEB_PREVIEW_v0.6.17.md) · [ADR 0029](ADR_0029_Operator_Executive_Preview_v0.6.17.md) ·
  [Registro CI](validation/OPERATOR_WEB_PREVIEW_CI_v0.6.17.md).

## v0.6.18 — revisões offline das contas locais (CANDIDATE)

- A — MVP: adicionar operadores, substituir grants exatos, habilitar/desabilitar e trocar senha em arquivo privado novo.
- Formato v1 e scrypt v0.6.11 preservados; origem cercada por SHA/identidade, publicação exclusiva sem overwrite e erros redigidos.
- Senhas em prompts ocultos; inspeção sem salts/hashes de senha. Não há recarga/revogação de sessões live ou endpoint de escrita.
- CI Linux/Windows com filesystem/crypto reais, isolamento de grants, startup snapshots, falhas e interrupção; pipelines Web/API/SQL permanecem compatíveis.
- Sem alteração de conta real, collector login, credenciais dos alvos, Node mTLS, migração, store, AD/SSO ou implantação no LAB.
- [Contrato](OPERATOR_ACCOUNTS_v0.6.18.md) · [ADR 0030](ADR_0030_Offline_Operator_Accounts_v0.6.18.md) ·
  [Registro CI](validation/OPERATOR_ACCOUNTS_CI_v0.6.18.md).

## v0.6.19 — auditoria privada opcional do servidor (CANDIDATE)

- A — MVP: registros de login, consultas/downloads, negações e encerramento do listener.
- JSONL novo/exclusivo por execução, operações fixas e IDs de sessão/grant autorizado; não copiar senhas, tokens, URLs ou conteúdo de relatório.
- Default off; 8 MiB/1024 bytes por registro, sequência serializada, reserva para fim dos requests e encerramento, fsync antes de novo trabalho.
- Auditoria indisponível nega novas operações antes de autenticação/SQL; falha depois da resposta preserva o prefixo e bloqueia admissões futuras.
- CI nativo Linux/Windows, HTTP, PostgreSQL SELECT-only e Chromium; política de contas, síntese e formatos ZIP preservados.
- Sem implantação no LAB, SIEM/imutabilidade/retenção automática, migração, store, AD/SSO, collector login ou alteração de mTLS.
- [Contrato](OPERATOR_SERVER_AUDIT_v0.6.19.md) · [ADR 0031](ADR_0031_Operator_Server_Audit_v0.6.19.md) ·
  [Registro CI](validation/OPERATOR_SERVER_AUDIT_CI_v0.6.19.md).

## v0.6.20 — revisão offline da auditoria (CANDIDATE)

- A — MVP: diagnóstico local somente leitura de arquivo privado até 8 MiB.
- Formato independente/estrito, sequência e pares; encerramento completo distinto de prefixo aberto ou cauda não interpretada.
- Saída agregada e SHA256 completo sem IDs/paths/linhas; exit 0 encerrado, 3 prefixo e 2 inválido/conflito.
- Drift observado bloqueia a revisão; não repara, apaga, reutiliza ou modifica registros. Produtor e contratos Web/API preservados.
- CI nativo Linux/Windows, saída abrupta em subprocesso, HTTP, Chromium e PostgreSQL SELECT-only sem alteração do LAB.
- Hash/estrutura não provam autoria, autorização real dos IDs, fsync durável ou entrega ao cliente; sem SIEM/retenção automática.
- [Contrato](OPERATOR_AUDIT_CHECK_v0.6.20.md) · [ADR 0032](ADR_0032_Offline_Operator_Audit_Check_v0.6.20.md) ·
  [Registro CI](validation/OPERATOR_AUDIT_CHECK_CI_v0.6.20.md).

## Incremento backend23–25 (07/10/2026)

[Workspace Model](WORKSPACE_MODEL_v0.6.25.md) e
[ADR0039](ADR_0039_Workspace_Model_v0.6.25.md) fixam histórico append-only,
observado/declarado, grafo manual limitado, revisão transacional e preview/apply
idempotente. O adapter registra operações como jobs e revalida respostas.
Categoria observada identity; sem backfill completo, UI/Mapper ou
ações em dispositivos. Gates adicionais: drift/replay, sessão perdida/rollback,
close durante commit/preparação, autoria/RLS/FKs A/B e isolamento de sources.
R03–R05 continuam parciais. API humana foi entregue em v0.6.26 e recovery isolado
em v0.6.27; R06 ainda depende de migração, readers/reports, audit e gates operacionais.
