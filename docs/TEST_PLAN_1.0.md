# Cancã — testes, gates e EVE-NG para 1.0

Revisão 06/10/2026 (-03). Casos planejados, não resultados PASS.
Evidência anteriormente aceita continua válida dentro do seu escopo/pin.

## Matriz

| ID | Cenário | Resultado obrigatório | Onde |
|---|---|---|---|
| T01 | Bases A/B, mesmos IP/hostname/serial externo; grants/reader sem bypass | SQL/API/search/report/cursor/download/cache/store/secret negam B; não mesclar identidades. | PG16/17 + HTTP |
| T02 | Site A; asset/interface/aresta/serviço referenciando B | FK/API rejeitam; intersite A aceita; parent site/submap cíclico rejeitado. | SQL/contratos |
| T03 | Abrir A/tentar B por aba/usuário/processo; fechar em scan/import/export; lease expirado/process-exit | Uma base ativa; sem replay live; intent/commit reconciliados; generation invalida respostas. | Concorrência/subprocesso/browser |
| T04 | Migração legada com assessments sobrepostos, checksums/grants/store e crash | Mapping explícito; bytes/IDs/hashes preservados; sem grant ampliado ou base implícita. | PG16/17 + LAB isolado |
| T05 | Reimport, IP reutilizado/serial genérico, tempo antigo/ausência parcial, conflito manual/observado | Idempotência/revisão/histórico; sem remoção ou fechamento implícito. | Fixtures/replay |
| T06 | Passivos/conversor/SFP/fibra, serviço/cluster, cycles/redundância | declared distinto de observed; mesmo inventário no mapa; travessia limitada/impacto potencial. | Grafo/UI |
| T07 | Export Windows11/Server/rede/referências, preview com drift, crash pre/post commit | Seleção/stubs visíveis; categories isoladas; nova prévia em drift; apply atômico/retry idempotente. | Filesystem/SQL/HTTP |
| T08 | Overview/abas/zoom/breadcrumb/submapas/camadas/teclado/janela pequena/logout/troca | Sem “Global” ambíguo; dados limpos; texto não executa HTML/scripts. | Chromium + LAB UX |
| T09 | LLDP/CDP/MAC/VLAN/trunk/impressora/VLAN trânsito/multi-MAC/AP/telefone | Cobertura exigida; hipótese L2/alternativas; falta de access local não recomenda remover VLAN. | Agents CI + EVE/vendors |
| T10 | AD senha/logon/privilégio/grupo/GPO/C:/patch canal/AD disabled/licença Graph | Limitações/timestamps; ausência de permission/sign-in não prova inatividade; identidade comprovada. | Mocks + Windows/AD/tenant LAB |
| T11 | Hypervisor/cluster/VM/datastore/clone/storage/backup | IDs/relações corretos; provisionado/usado/livre separados; API/cobertura registrados. | Fixtures + hypervisor LAB |
| T12 | MIB/OID/feed vencido/build incompatível/icon inválido/zip traversal | Parser limitado sem execução; fonte/hash/licença; não avaliado sem catálogo; override privado isolado. | CI + LAB offline |
| T13 | Backup global/individual com revisão concorrente, restore/collision, perda da secret key | Par DB/store coerente; backup individual sem outras bases; jobs/contas/secrets revisados. | PG16/17 + LAB recovery |
| T14 | 100/1.000/10.000 objetos, 500 nós/2.000 arestas, 20 trocas/import/export concorrente | Consultas limitadas; bases fechadas não materializadas; RAM sem crescimento inexplicado; p50/p95/hardware publicados. | Benchmark + LAB |
| T15 | Reports técnico/executivo/custom/action por revisão/site/ambiente | Totais reproduzíveis; idade/cobertura explícitas; ações/horizontes sem apagar história. | Snapshots + revisão humana |
| T16 | Instalação/upgrade/rollback/SBOM/matriz/roles/TLS/compat | Zero blockers de dados/segurança; limitações claras; downgrade via recuperação qualificada. | Packaging + LAB GA |

Executar com commit/config/hardware/runtime/permissões e casos PASS/FAIL/SKIP,
hashes/fontes/limites. CI sintético não é aceite de vendor. Negativas comprovam
ausência de mutação/acesso, não só exit code.

## Gates

| Fase | Exige |
|---|---|
| Alpha estendida | R01–R06; T01–T07/recovery base; PG16/17/nativo/HTTP; LAB isolado migração/isolation; antigas pendências explícitas. |
| v0.7 | UI/wizard/Mapper manual/zoom/submapas/passivos; T06/T08/T14; mantenedor valida navegação/trocas. |
| v0.8 | Rede/AD/Compute/virtualização/inferência/serviços; T09–T11; perfil real por integração anunciada e contraprovas. |
| v0.8.x / Beta | Graph/catálogos/perfis selecionados/T12; instalação/security/CLA/matriz/SBOM/limites Community. |
| v0.9 / RC | T13/T15; ações/custom reports/hardening/feature freeze/upgrade/recovery/feedback externo controlado. |
| GA 1.0 | T16/regressão afetada, matriz oficial/docs operacionais/zero blockers; suporte profundo só onde qualificado. |

Não repetir instalação/restore/lifecycle/Web R1/scheduler R1/soak curto/SNMP CI
aceitos sem alteração de contrato. Downloads v0.6.13+ e produção roles/TLS/recovery
pendentes seguem CANDIDATE; consolidar gates afetados na nova release.
Nenhum teste humano solicitado agora: este turno prepara o plano.

## EVE-NG incremental

Reusar P01-MGMT01/DC01/W11/Linux Ubuntu/Rocky conforme disponibilidade. Antes de
executar, confirmar IPs/rotas/tempo/disco/scopes atuais; não supor acesso remoto.

| Rodada | Montagem pequena | Comprova | Limite |
|---|---|---|---|
| E0 core | PostgreSQL + fixtures A/B sem rede | Migração/isolation/imports/carga/recovery | Sem vendor real |
| E1 rede L2 | 2 switches virtuais + endpoints/VLAN/access/trunk | Portas/VLAN/MAC/LLDP suportados e contraprovas de trânsito | Sem ASIC/transceiver/counters físicos específicos |
| E2 downstream | Bridge Linux com 2+ endpoints; fixture AP/telefone | Multi-MAC/hipótese/confidence/alternativas | Não prova hub físico |
| E3 sites/L3 | Router/firewall + 2 sites/CIDRs sobrepostos/VRFs | Namespace/intersite/cloud declarado/submaps | Cross-workspace sempre negado |
| E4 compute/AD | LAB existente + dados/permissões controlados | AD/capacidade/cobertura/patch feed | Timestamp AD não é campo livre para simular |
| E5 virtualização | Um hypervisor por rodada; API fixtures antes de nested | host/VM/datastore/cluster/permissões | Não todos juntos nem performance de produção |
| E6 Graph/feeds | Tenant LAB consentido + fixtures/catálogo offline | Licença/correlação/negação/falta de dado | EVE não emula Graph/catálogo atual |
| E7 release | Dataset consolidado + recovery/browser | Fluxo 1.0/UX/capacidade | Sem NMS/remediação |

Usar imagens legitimamente disponíveis ao mantenedor, sem distribuí-las no Git.
Registrar vendor/versão/OIDs/API/config/limitações. Ligar somente a rodada corrente
para poupar recursos. MIB fixtures/agents ajudam sem firmware real. Impressora,
UPS/câmera/storage começam em perfil genérico/fixture, com teste real para claim real.

Secret Provider mantém credenciais. Outputs reais/capturas ficam em OneDrive;
Git guarda fixtures sanitizadas e qualificação técnica. “Ações” do LAB são planos
e recomendações, não comandos automáticos de remediação.
