# Cancã — Open Infrastructure Assessment & Intelligence Platform

![Cancã — identidade visual conceito v1](docs/branding/canca-brand-concept-v1.jpg)

> **Orizon IT — Produto 01 (P01)**  
> **Cancã — Open Infrastructure Assessment & Intelligence Platform**  
> Plataforma open-source em desenvolvimento para discovery, inventário, análise de configuração, assessment, evidência técnica e inteligência de infraestrutura.

**Cancã** é o nome oficial do produto. O identificador **P01** permanece temporariamente em nomes de arquivos, schemas, headers e artefatos internos durante a fase Technical Alpha para preservar compatibilidade e rastreabilidade dos testes. A migração dos identificadores internos será feita de forma controlada, sem quebrar contratos já validados.

## Product baseline

Operator administration v0.6.18: [private offline account revisions](docs/OPERATOR_ACCOUNTS_v0.6.18.md)
(CANDIDATE). Add operators, replace exact read grants, enable/disable and rotate
passwords into a new private file for controlled restart. Live policies stay immutable;
development/CI need no manual LAB action.
Operator Web v0.6.17: [executive preview in the Web](docs/OPERATOR_WEB_PREVIEW_v0.6.17.md)
(CANDIDATE). Complete fenced historical coverage, recorded severities and paginated
recommendations; the existing technical/executive ZIP formats remain unchanged.
Development and CI continue independently of postponed manual LAB tests.
Operator Web v0.6.16: [selection of own permitted assessments](docs/OPERATOR_ASSESSMENT_SELECTION_v0.6.16.md)
(CANDIDATE). Session policy IDs only, independent of PostgreSQL availability;
selection fills the form for an explicit report query. Manual LAB tests remain deferred.
Operator Web v0.6.15: [executive report download](docs/OPERATOR_WEB_EXECUTIVE_v0.6.15.md)
(CANDIDATE). Technical download remains compatible with its v0.6.13 file format;
manual LAB gates remain deferred and historical install guides use their Git pins.
Executive report v0.6.14: [historical coverage and consolidated recommendations](docs/EXECUTIVE_REPORT_v0.6.14.md)
(local read-only CLI, CANDIDATE). Development and CI qualification are independent
of postponed manual LAB tests; the pinned v0.6.13 Web package is preserved.
Operator Web v0.6.13: [complete report download](docs/OPERATOR_WEB_EXPORT_v0.6.13.md)
(CANDIDATE). Web v0.6.12: [local login and read-only reports](server/README.md)
(short synthetic browser R1 [LAB VALIDATED](docs/validation/LOCAL_OPERATOR_WEB_P01LAB_R1_v0.6.12.md);
wider release CANDIDATE). API v0.6.11 same-host R1 is
[LAB VALIDATED](docs/validation/LOCAL_OPERATOR_P01LAB_R1_v0.6.11.md).
Portable collection needs no Cancã login; target credentials and
connected node mTLS retain their separate purposes. Optional AD integration follows.

- [MVP 1.0](docs/MVP.md)
- [Project Governance](docs/PROJECT_GOVERNANCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Engineering Roadmap](docs/ROADMAP.md)
- [Source of Truth — GitHub x OneDrive/SharePoint](docs/SOURCE_OF_TRUTH.md)
- [Brand identity](docs/branding/README.md)

## Status de engenharia

- **Windows / AD Collector:** 0.3.0 — candidate, validado em LAB para coleta local/AD, FTP e SMB; teste específico de AD stale ainda precisa de validação com técnica compatível com atributos system-managed.
- **Linux Collector:** 0.3.0 — candidate, validado em LAB em Ubuntu e Rocky para SSH, FTP, Samba, password policy, serviços e plataforma.
- **Analyzer / Rule Engine:** 0.2.0 — candidate, 19 regras determinísticas e rastreabilidade para a evidência de origem.
- **Network Discovery Scanner:** 0.4.1 — LAB VALIDATED para o core não autenticado no cenário atual; produção/cobertura corporativa ainda em expansão, sem credenciais, criado para descoberta por múltiplos ranges antes do deep discovery.
- **Credential Manager:** 0.4b.6 — mantém Secret Provider e matching compatível com v0.4b, acrescentando taxonomy de realm/target/privilege/purpose, evidence gates e lint de placeholders.
- **SSH Credentialed Enrichment:** 0.4b.2.1 — LAB VALIDATED em Ubuntu e Rocky via P01-MGMT01; appliance SSH restrito também classificado corretamente.
- **Context-aware Credential Resolver / Planner:** 0.4b.3.2 — v0.4b.3.1 LAB VALIDATED; candidate passa a consumir Assessment Manifest, distinguir realm declarado/observado e bloquear conflito de contexto.
- **WinRM Credentialed Enrichment:** 0.4b.4.3 — LAB VALIDATED em P01-MGMT01 (local realm), P01-DC01 (domain controller/domain realm) e P01-W11-01 (domain workstation); failure semantics transport/auth também validados em runtime.
- **Multi-target Credentialed Executor:** 0.4b.5 — LAB VALIDATED em dry-run, AUTH-only e FULL nos cinco ativos P01LAB; SHA256 binding, profile-drift guard e shared-credential circuit breaker.
- **Assessment Context & Credential Intake:** 0.4b.6 — LAB VALIDATED; manifest não secreto, intake estruturado, declared/observed realm gating e high-privilege guardrails.
- **Asset Resolver:** 0.4c.0 — LAB VALIDATED; 5 Network Discovery + 5 FULL observations -> 5 logical assets, 0 unresolved, 0 ambiguous, 0 conflicts.
- **Evidence Bundle:** 0.5a.0 — LAB VALIDATED; `.p01bundle` único para connected/offline transport, 8-artifact P01LAB bundle, SHA256 inventory e secret-material guard.
- **Offline Import:** 0.5b.0 — LAB VALIDATED; import idempotente, raw evidence preservation, receipt JSON/SHA256 e server-side Asset Resolver replay com semantic_match=true.
- **Central Ingestion API:** 0.5c.1 — LAB VALIDATED; localhost ingestion, idempotência, status lookup, semantic equivalence, negative gates e connection hygiene.
- **Connected Discovery Node Upload:** 0.5d.0 — LAB VALIDATED; HTTPS/mTLS, identidade do node ligada ao certificado e ao bundle, upload outbound, idempotência e transporte cross-host Windows→Linux validados.
- **Portable Discovery Node Runtime:** 0.5e.6 — LAB VALIDATED; fluxo end-to-end completo no P01LAB, incluindo Evidence Bundle workspace-driven, Connected Upload mTLS e zero-input resume sem segunda conexão.
- **Central Persistence / Asset Registry:** 0.6.3 — CANDIDATE para LAB; índice PostgreSQL, API opt-in v0.6.1, lifecycle v0.6.2 e identidade persistente por assessment com proveniência e revisão de ambiguidades. [Assets](docs/ASSET_REGISTRY_v0.6.3.md), [lifecycle](docs/ASSESSMENT_LIFECYCLE_v0.6.2.md), [integração](docs/INGESTION_INDEX_v0.6.1.md) e [próximos passos](docs/NEXT_STEPS_v0.6.0.md).
- **Optional Service Scheduler:** 0.5f.3 — LAB VALIDATED para R1 curto e soak estendido offline de 10 ticks em Windows/Rocky; default off, revisão após interrupção e zero replay. Multi-day e etapas live pendentes. [Status](docs/STATUS_SCHEDULER_v0.5f.3.md).
- **Reporting Engine:** relatório técnico/exportação v0.6.9 LAB VALIDATED no R1 sintético; download Web v0.6.13 e resumo executivo v0.6.14 CANDIDATE, com gates operacionais independentes.

> Saídas reais de discovery devem ser tratadas como **CONFIDENCIAL — DADOS DO CLIENTE**.

## Arquitetura alvo

```mermaid
flowchart LR
    OP[Operador] --> NDS[Network Discovery]
    NDS --> RES[Asset Resolver]
    RES --> WC[Windows/AD Collector]
    RES --> LC[Linux Collector]
    RES --> FUT[SNMP/SSH/WinRM Enrichment]
    WC --> EV[JSON + SHA256]
    LC --> EV
    FUT --> EV
    EV --> ANA[Analyzer / Rule Engine]
    ANA --> REP[Reporting Engine]
```

O scanner **descobre**. Os collectors **aprofundam**. O Asset Resolver **deduplica**. O Analyzer **interpreta evidências**. O Reporting Engine **apresenta**.

## Estrutura do repositório

```text
.
├── analyzer/
│   ├── P01_Discovery_Analyzer.py
│   ├── P01_Rules.json
│   └── README.md
├── collectors/
│   ├── linux/
│   │   └── P01_Linux_Discovery_Collector.py
│   └── windows/
│       └── P01_Windows_AD_Discovery_Collector.ps1
├── connected/
│   ├── P01_Discovery_Node_Uploader.py
│   └── README.md
├── credentialed_enrichment/
│   ├── P01_SSH_Enricher.py
│   ├── requirements-ssh.txt
│   ├── P01_WinRM_Enricher.py
│   ├── requirements-winrm.txt
│   ├── README-WINRM.md
│   └── README.md
├── asset_resolver/
│   ├── P01_Asset_Resolver.py
│   └── README.md
├── ingestion/
│   ├── P01_Offline_Import.py
│   └── README.md
├── evidence_bundle/
│   ├── P01_Evidence_Bundle.py
│   └── README.md
├── runtime/
│   ├── P01_Discovery_Node.py
│   └── README.md
├── network_discovery/
│   ├── P01_Network_Discovery_Scanner.py
│   ├── targets.example.txt
│   ├── excludes.example.txt
│   └── README.md
├── schemas/
│   ├── p01-discovery-schema-v0.2.json
│   └── p01-discovery-schema-v0.3.json
├── tests/
│   └── test_network_discovery.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── VALIDATION.md
│   ├── SOURCE_OF_TRUTH.md
│   ├── ROADMAP.md
│   └── validation/
└── .github/workflows/
```

## Uso — Portable Discovery Node v0.5e

A v0.5e.6 fecha o fluxo portátil end-to-end até o Connected Upload:

```powershell
python .\runtime\P01_Discovery_Node.py doctor --workspace-root C:\Canca\runs
```

Em seguida, o operador cria um workspace isolado com `init`, executa Network Discovery autorizado com `run` e executa novamente `run` para gerar o Credential Plan seguro. O `status` acompanha checkpoints; `export` gera o mesmo `.p01bundle` homologado e `upload` usa o transporte mTLS v0.5d.

Após o Asset Resolver, `export --workspace <path>` gera o `.p01bundle` do state. O primeiro `upload` exige os parâmetros mTLS; após concluir, `upload --workspace <path>` retorna `already_complete` sem abrir nova conexão.

Veja [runtime/README.md](runtime/README.md).

## Uso — Network Discovery v0.4a

A execução requer confirmação explícita de que o operador está autorizado a varrer o escopo.

```powershell
python .\network_discovery\P01_Network_Discovery_Scanner.py `
  --target 192.168.1.0/24 `
  --profile safe `
  --workers 64 `
  --run-label CASA-LAB `
  --output-dir .\output `
  --ack-authorized-scan
```

Múltiplas faixas e exclusões:

```powershell
python .\network_discovery\P01_Network_Discovery_Scanner.py `
  --target 10.10.10.0/24 `
  --target 10.10.20.0/24 `
  --exclude 10.10.10.200-220 `
  --profile safe `
  --ack-authorized-scan
```

A v0.4a **não tenta credenciais**. Credential Manager, SNMP, SSH e WinRM entram na v0.4b.

## Uso — collectors

Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\collectors\windows\P01_Windows_AD_Discovery_Collector.ps1 `
  -OutputDirectory C:\P01\output `
  -RunLabel LAB-P01 `
  -IncludeIdentityDetails
```

Linux:

```bash
python3 ./collectors/linux/P01_Linux_Discovery_Collector.py \
  --output-dir ./output \
  --run-label LAB-P01
```

## Uso — Analyzer

```bash
python3 ./analyzer/P01_Discovery_Analyzer.py \
  --input-dir ./inputs \
  --output-dir ./output \
  --rules-file ./analyzer/P01_Rules.json \
  --run-label LAB-P01
```

## AD stale

`lastLogonTimestamp` é administrado pelo Active Directory e não deve ser tratado como um campo livremente editável para simulação. A validação do caminho de stale deve usar threshold reduzido em objetos que nunca logaram e testes sintéticos. O threshold operacional padrão permanece 90 dias. Veja [docs/validation/AD_STALE_v0.3.md](docs/validation/AD_STALE_v0.3.md).

## GitHub x OneDrive/SharePoint

O **GitHub é a fonte de verdade de engenharia**: código, testes, schemas, rulesets, documentação técnica, CI, issues e histórico de commits.

O **OneDrive/SharePoint é a fonte de verdade de produto, governança e evidência**: CI do produto, oferta comercial, LAB, resultados brutos, JSON/SHA256 de validação, relatórios, entregáveis e snapshots formais de release. Google Drive pessoal permanece legado durante a migração autorizada.

Não devem existir duas cópias editáveis concorrentes do mesmo código. Veja [docs/SOURCE_OF_TRUTH.md](docs/SOURCE_OF_TRUTH.md).


## Licenciamento e comunidade

Cancã Community adota a **Apache License 2.0**, identificador **Apache-2.0**. Consulte [LICENSE](LICENSE) e [NOTICE](NOTICE).

A estratégia aprovada é lançar primeiro uma **Community estável** e, posteriormente,
uma **edição comercial** com módulos específicos e sem cota comercial de itens.
Os limites de funcionalidades e quantidade da distribuição oficial Community serão
definidos antes do lançamento; nenhuma cota nova foi implementada nesta alteração.
Limites técnicos de segurança e capacidade continuam válidos em todas as edições.

Apache 2.0 permite uso comercial, modificações e redistribuição, inclusive forks
que alterem limites presentes no código aberto, respeitando a licença e os avisos.
Os futuros módulos comerciais terão código/licença próprios; a base aberta
continuará sob Apache 2.0. A licença não concede uso irrestrito das marcas
**Cancã** e **Orizon IT**.

Contribuições externas serão feitas sob Apache 2.0; o processo de CLA Orizon IT,
seu texto final e sua aplicação operacional serão concluídos antes da abertura
pública de contribuições. O CLA não é requisito para executar a Community.

[Política de licença e edições](docs/LICENSING_AND_EDITIONS.md) ·
[Decisão de migração](docs/ADR_0021_Apache_2_0_and_Editions.md).

## Segurança

- nunca commitar credenciais, tokens, chaves privadas ou outputs reais de clientes;
- network discovery somente em escopo explicitamente autorizado;
- credentialed discovery deve usar Secret Provider e least privilege;
- nenhuma senha deve aparecer em JSON, logs ou rulesets;
- collectors são read-only first;
- network scanning é ativo, mas não deve explorar vulnerabilidades;
- limites de concorrência e scope são guardrails de produto.

## Versionamento

O repositório preserva histórico por **commits, branches, tags e releases**. O código-fonte principal não precisa manter cópias duplicadas por versão. Schemas podem coexistir quando compatibilidade exigir.

## Próximas fases

1. v0.6.x — Product Alpha: PostgreSQL, lifecycle, identidade persistente, API/UI mínima e reporting. Fundação v0.6.0 e integração v0.6.1 CANDIDATE.
2. Em paralelo: soak estendido do scheduler v0.5f.3; R1 curto Windows/Rocky já aprovado.
3. v0.7.x — Design Partner Alpha em ambientes externos controlados.
4. v0.8.x — Community Beta; v0.9.x — Release Candidate; v1.0 — GA.
5. Adapters adicionais, CVE correlation, Patch Compliance e topologia conforme classificação MVP/post-MVP.

Mais detalhes: [docs/ROADMAP.md](docs/ROADMAP.md).

---

**Cancã — Open Infrastructure Assessment & Intelligence Platform**  
**Orizon IT — Tecnologia que transforma negócios.**


## Optional agent track

Agent foundation and manual Windows/Linux services passed LAB. Scheduler v0.5f.3
passed the short offline R1 on both hosts; extended soak remains pending. See the
[agent guide](agent/README.md) and [next steps](docs/NEXT_STEPS_v0.6.0.md).
The canonical portable runtime remains v0.5e.6 and is supported independently.

### Findings v0.6.4 CANDIDATE

Persistência explícita de findings com catálogo/engine/hash de origem, cobertura
WinRM de Firewall e secure channel e replay imutável. Sem fechamento automático.
[Guia](docs/FINDINGS_v0.6.4.md) · [Status](docs/STATUS_FINDINGS_v0.6.4.md).

### Relatório consolidado v0.6.5 CANDIDATE

Consulta somente leitura de lifecycle, identidade, cobertura e ocorrências
históricas por assessment, com paginação vinculada a um escopo consistente.
[Guia](docs/ASSESSMENT_REPORT_v0.6.5.md) · [Status](docs/STATUS_ASSESSMENT_REPORT_v0.6.5.md).

### Backup/restore v0.6.6 CANDIDATE

Qualificação CI do par banco/store com dump e restauração reais em PostgreSQL 16/17,
comparação das 14 tabelas, relatório, revalidação de evidências e replay sem mutação.
Fixture CI descartável; recuperação sintética R1 do LAB aceita em v0.6.7, roles completos pendentes.
[Guia](docs/BACKUP_RESTORE_v0.6.6.md) · [Status](docs/STATUS_BACKUP_RESTORE_v0.6.6.md).

### Verificação de recuperação LAB v0.6.7 LAB VALIDATED (R1 sintético)

R1 básico PostgreSQL 16.15/Rocky aprovado no escopo sintético de import/assets/findings/reader.
Helper capture/verify somente leitura compara 14 tabelas e bytes/projeções do store na fixture
isolada antes/depois do restore. [Aceite R1](docs/validation/POSTGRESQL_P01LAB_R1_v0.6.5.md) ·
[Roteiro de recuperação](docs/LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md) · [ADR 0018](docs/ADR_0018_LAB_Recovery_Check_v0.6.7.md).

### Lifecycle/paginação LAB v0.6.8 CANDIDATE

Recuperação sintética R1 v0.6.7 aprovada no Rocky/PostgreSQL 16.15: 14 tabelas/20 arquivos,
fontes revalidadas e replay sem mudança. Helper v0.6.8 prepara quatro transições e paginação
com retomada, replay e conflitos na base recuperada.
[Aceite recuperação](docs/validation/POSTGRESQL_P01LAB_RECOVERY_R1_v0.6.7.md) ·
[Roteiro v0.6.8](docs/LAB_POSTGRESQL_LIFECYCLE_R1_v0.6.8.md) · [Status](docs/STATUS_LAB_LIFECYCLE_v0.6.8.md).
