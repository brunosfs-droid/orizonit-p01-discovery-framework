# Cancã — Engineering Roadmap

> Cancã is Orizon IT Product 01 (P01). Existing P01 identifiers remain valid during Technical Alpha for compatibility.

## Product maturity path

1. **Technical Alpha — current:** core discovery, credentialed enrichment, Asset Resolver, Evidence Bundle, offline/connected ingestion and mTLS contracts.
2. **Distributed Technical Alpha — next gate:** Discovery Node and Cancã Server on separate hosts with outbound-only mTLS.
3. **Product Alpha:** PostgreSQL persistence, assessment lifecycle, minimal Web/API surface and end-to-end reporting.
4. **Design Partner Alpha:** controlled external environments and support-matrix expansion.
5. **Community Beta:** public open-source readiness, installation, CLA process, SECURITY/CONTRIBUTING, SBOM and third-party license inventory.
6. **Release Candidate:** feature freeze, hardening, upgrade/rollback, backup/restore and blocker closure.
7. **1.0 GA:** supportable end-to-end Assessment & Intelligence product.

See [MVP.md](MVP.md) and [PROJECT_GOVERNANCE.md](PROJECT_GOVERNANCE.md).


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

### v0.4b.7+ — próximos adapters
- SNMPv3/SNMPv2c;
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

### Próximas iterações v0.4c
- AD computer object / objectGUID / SID;
- system UUID / SMBIOS UUID / service tag;
- Windows Collector e Linux Collector locais;
- registry persistente de asset IDs entre assessment runs;
- SNMP sysName/sysObjectID e VMware identifiers futuramente.

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
- **v0.5f.3:** planned — scheduling/restart/recovery hardening and soak.
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

Follow-up: após fechar v0.5e, iniciar v0.5f Optional Installed Service/Agent e os gates de product alpha/persistência central.


### v0.5f.3 — Explicit bounded service scheduling (CANDIDATE)
- Shared scheduler around canonical run_once; default off, operator opt-in after installation.
- Fixed delay 60..86400s after completion, bounded attempts, policy reread and native workspace lock.
- Running/halted session journal blocks restart and manual-mode bypass until reviewed.
- OS start remains manual with no recovery/retry/timer; stop wakes wait cooperatively.
- Native scheduled R1 uses real 60s spacing and interrupted-wait review on SCM/systemd.
- [Status](STATUS_SCHEDULER_v0.5f.3.md), [ADR 0010](ADR_0010_Scheduler_v0.5f.3.md), [LAB R1](LAB_SCHEDULER_v0.5f.3_R1.md).
- Windows/Rocky LAB, multi-day soak and live service principal qualification remain separate gates.
