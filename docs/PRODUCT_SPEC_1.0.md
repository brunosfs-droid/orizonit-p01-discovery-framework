# Cancã 1.0 — especificação consolidada

Revisão 2 — 06/10/2026, America/Sao_Paulo. Decisões de produto aprovadas por
Bruno Feitoza; detalhes de engenharia abaixo definem a execução.
Baseline executável: **v0.6.20 CANDIDATE**, SNMP **v0.4b.9 CANDIDATE**.
Esta revisão é planejamento: funcionalidades novas ainda não estão implementadas.

## Experiência e propósito

Descobrir, modelar, correlacionar, avaliar, explicar e planejar a infraestrutura
de um workspace, usando scans explícitos e importações manuais/connected.
O usuário mantém uma base histórica e gera relatórios de estado atual ou de uma
coleta específica. A 1.0 não depende de polling contínuo ou monitoramento 24×7.

O Mapper é parte central da 1.0, junto de páginas de objetos, inventário,
findings, desenho de serviços e planejamento de ações. Tabelas servem para
filtro e exportação; o produto não se resume a uma tabela de propriedades.

## Escopos e linguagem da interface

| Conceito | Significado e regra |
|---|---|
| Servidor | Instalação do Cancã; administra acesso, catálogo de workspaces, recursos, backups e catálogos compartilhados. |
| Workspace | Base isolada de uma organização/cliente/projeto. Vários podem ser armazenados; somente um aberto por instalação na 1.0. |
| Ambiente | Recorte lógico opcional dentro do workspace, como Produção, Homologação ou LAB. Não cria um segundo tenant. |
| Site | Localização física ou lógica pertencente a um único workspace: matriz, filial, datacenter, Azure ou AWS. Pode atender mais de um ambiente do mesmo workspace. |
| Visão geral do workspace | Nível mais amplo do Mapper do workspace aberto; nunca agrega outros workspaces. |
| Administração do servidor | Configuração da instalação; separada do Mapper e da navegação dos dados. |

Não usar um botão ambíguo “Global”. No Mapper usar **Visão geral do workspace**;
para configurações usar **Administração do servidor**. Uma relação pode atravessar
sites e ambientes do mesmo workspace. Nenhum ativo, serviço, vínculo, inferência,
credencial, resultado de busca ou relatório pode interagir com outro workspace.
Endereços e nomes idênticos em bases diferentes são permitidos sem correlação.

Organization é metadado do workspace, sem hierarquia de tenants acima dele.
Os diretórios chamados `workspace` no collector atual são diretórios de execução
de scan, não o novo Workspace de produto.

## Fluxos obrigatórios

1. Administrador cria workspace e define acesso. Ao abrir, carrega apenas seu
   contexto e consultas paginadas; os demais permanecem armazenados e fechados.
2. Primeiro scan/import oferece criar workspace, selecionar ambiente/site ou
   manter objetos “Sem site”. Criação pelo scanner é intenção/export; criar
   a base no servidor exige autorização própria.
3. Atualização: escolher workspace aberto, ambiente/site e categorias, verificar
   pacote e mostrar prévia de identidade, novos/alterados, conflitos, cobertura
   e relações. Aplicação explícita vinculada à revisão da prévia.
4. Resolver identidades ambíguas antes de associar. Políticas: merge revisado,
   criar base independente ou guardar somente evidência. Duplicação intencional
   exige identidade nova justificada; não duplicar automaticamente a cada scan.
5. Navegar por dashboard, mapa, sites, objetos e problemas; editar declarações
   manuais e dependências sem alterar a evidência original.
6. Gerar relatórios técnicos/executivos/customizados e ações; fixar coleta/revisão,
   período, escopo, filtros e versões de regras/catálogos.
7. Fechar workspace e liberar tarefas/caches/visualizações antes de abrir outro.

Scan standalone e scan iniciado pela interface do servidor usam o mesmo pipeline
de autorização/coleta/bundle. O standalone continua sem login Cancã para coletar;
credenciais de alvos, login humano e mTLS dos Nodes continuam separados.

## Navegação

| Área | Conteúdo |
|---|---|
| Visão geral | Última coleta, ativos, cobertura, idade das fontes, findings e capacidade com links para evidências. |
| Mapper | Mapas/submapas, sites locais/remotos, on-premises, nuvens, hosts/VMs e camadas física, L2, L3, virtualização, serviços, findings. |
| Inventário | Objetos filtráveis, busca e exportação por classe, sistema, site, ambiente e categoria. |
| Redes | IPs/sub-redes, VLANs, interfaces, portas, trunks, MACs e LLDP/CDP conforme cobertura. |
| Identidade | AD: usuários, computadores, grupos, privilégios, políticas, GPOs e findings. |
| Compute | Windows/Linux: SO, hardware, discos, patches, software e drivers/firmware. |
| Virtualização | Cluster, host, datastore, rede e VM; CPU/RAM/disco usados e provisionados diferenciados. |
| Cloud e Microsoft 365 | Configuração Graph por workspace, licenças, contas e correlação AD/Entra. |
| Storage e backup | Dispositivos, capacidade e evidências disponíveis de proteção dos dados. |
| Serviços / Desenho | Dependências declaradas/observadas e impacto potencial; reutiliza objetos do inventário. |
| Findings e ações | Evidências, confiança, severidade, recomendações, responsáveis, prioridades e candidatos a mudança. |
| Relatórios | Dashboards, relatórios técnicos/executivos/customizados e planos por horizonte. |
| Coletas | Runs, imports, cobertura, diferenças, histórico, falhas e revisão de identidade. |

Administração do servidor contém workspaces, contas/permissões, capacidade,
backup/restore, Catalogs & Knowledge, importação/exportação de MIBs, mappings OID,
catálogos de atualização, baselines e pacotes de ícones/imagens. Adaptações
particulares de um cliente ficam no workspace; não enriquecem outros por acidente.

## Páginas de objetos e Mapper

Página comum: identidade, tipo, fabricante/modelo/serial, localização,
proveniência, última observação, cobertura, relações, findings, histórico e notas.
Abas especializadas: switch tem interfaces/VLANs/MACs/vizinhos; Windows tem
discos/SO/patches/drivers/AD; hypervisor tem cluster/datastores/redes/VMs.

Zoom semântico: workspace → grupos/sites/nuvens → redes/equipamentos → portas,
componentes/VMs. Breadcrumb e ação de entrar/sair acompanham o zoom. Agrupar
grandes conjuntos e carregar subgrafos sob demanda. Camadas/desenhos são
projeções do mesmo modelo, não inventários independentes. Persistir posições,
grupos e submapas por workspace.

Objetos sem IP: conversor fibra/UTP, patch panel, hub, cabo, serviço, componente
passivo, SFP/GBIC. Registrar fabricante/modelo, porta, fibra mono ou multimodo,
conector e origem declarada. Relações manuais têm autoria/revisão.
Ícones/imagens e packs exportáveis respeitam licença e limites de arquivo.
Desenho de cluster agrega membros existentes sem duplicar equipamentos.

## Inteligência e evidência

Separar **origem** (`observed`, `declared`, `inferred`) de **resolução**
(`known`, `unknown`, `conflicting`) e de **confiança**. Ausência de coleta não
é saúde comprovada. Informação manual nunca aparece como descoberta automática.

| Domínio | Análises alvo da 1.0 e pré-condição |
|---|---|
| Rede | Endpoint/impressora em trunk, múltiplos MACs em access, inconsistência de trunk/native VLAN e VLAN aparentemente ociosa; requer portas, VLANs, MACs e contexto dos vizinhos. |
| Inferência L2 | Vários MACs numa porta sem vizinho identificado podem indicar segmento downstream. Mostrar alternativas (switch não gerenciável, bridge, AP, telefone), confiança/evidências; não afirmar hub como fato. |
| AD | Contas sem logon/senha antiga/nunca expira, privilégios diretos/herdados, grupos vazios, GPO vazia ou sem vínculo; respeitar limitações de timestamps e abrangência. |
| Windows/Linux | Capacidade (incluindo C: com menos de 10% livre), patches/EOL e confronto com catálogo de produto/build/edição/canal; drivers/firmware somente com catálogo aplicável. |
| Virtualização | Host/cluster/VM/datastore, CPU/RAM/discos; capacidade virtual/provisionada não equivale a consumo real no storage. |
| M365/Entra | Licenças atribuídas/disponíveis, AD desabilitado com licença, inatividade com licença. Correlacionar identidades comprovadas; last sign-in ausente não prova inatividade. Custo exige preço/moeda/período declarados. |
| Serviços | Dependências, redundância declarada e impacto potencial de finding; não declarar indisponibilidade real a partir de scan. |

“VLAN não utilizada” exige cobertura suficiente e considera trânsito/VMs/rotas;
não recomendar remoção só por não haver porta access local. Catálogo vencido ou
incompleto produz não avaliado/limitação. Remediação é recomendação, sem mudança
de configuração automática.

## Matriz inicial de suporte a qualificar

Alvos de entrega, não suporte já demonstrado. Profundidade exige contrato por
seção, testes e limitações; não significa todos os vendors/modelos.

| Classe | Alvo 1.0 | Sequência |
|---|---|---|
| Windows Server/workstation, Linux, AD | Coleta detalhada e regras rastreáveis | Primeiro |
| Switch/router | SNMP read-only, portas, VLANs, MACs, vizinhos por perfil | Primeiro |
| Firewall | Identificação genérica e perfis selecionados | Incremental |
| VMware, Hyper-V, Proxmox | Host/cluster/VM/datastore e relações detalhadas | Incremental prioritário |
| KVM/libvirt | Inventário funcional | Incremental |
| Xen | Identificação/import inicial, profundidade declarada | Incremental |
| Microsoft 365/Entra | Graph e correlação AD | Incremental prioritário |
| Impressora, UPS, AP, telefone IP | Genérico/SNMP/LLDP e perfil por modelo | Incremental |
| Storage/NAS/SAN | SNMP/API/import por perfil qualificado | Incremental |
| Câmera/CFTV | Manual/identificação; SNMP/ONVIF quando disponível e autorizado | Incremental |
| Hub/conversor/SFP/passivos | Manual; inferência separada de observação | Mapper inicial |

Expandir modelos por atualização. Objeto manual/genérico não implica adapter
qualificado. GA publica a matriz real por fabricante/firmware/API, permissões,
campos e limitações. Ausência de qualificação impede anunciar suporte profundo.
Reduzir alvo acordado exige decisão registrada, sem exclusão silenciosa.

## Relatórios, backup e extensão

Finding → recomendação → ação → candidato a mudança. Ação tem responsável,
prioridade, esforço/dependências e horizonte editável (0–30, 31–90, 91–180 dias
como defaults). Estado da ação não apaga ocorrência histórica. Não executar
mudanças; ITSM pode vir depois. Estado atual informa idade/cobertura/conflitos.

Backup do servidor inclui registro de workspaces, banco/store, mapas, declarações,
relações, regras/catálogos/MIBs, ícones/configurações e permissões. Backup de
workspace não traz outros. Secrets/chaves têm proteção/restauração próprias;
relatórios não os incluem. Restore qualificado é gate da GA.

MIB não equivale a adapter: OID → atributo semântico → unidade/tipo → regra é
versionado. Preferir feeds/APIs/imports de fabricante; scraping não é dependência
central. Catálogos offline exibem fonte/hash/licença/validade/compatibilidade.

## Escopo e estratégia

Fora da 1.0: NMS contínuo, simulação de pacotes, exploração, patch deployment,
remediação automática, IPAM/CMDB enterprise completos, billing/marketplace,
SaaS público multi-tenant e comando remoto arbitrário. Scheduler existente
permanece default off e não transforma o produto em monitoramento.

Apache-2.0 e Community primeiro permanecem. Cotas e módulos comerciais não foram
definidos. O fluxo workspace/Mapper/assessment precisa ser útil na Community;
alocação de profundidade/módulos deve ser publicada antes da Beta, sem enforcement
introduzido por esta revisão.

## Execução

- [Arquitetura](ARCHITECTURE.md) e [ADR 0036](ADR_0036_Workspace_First_1.0.md).
- [Implementação/migração](IMPLEMENTATION_PLAN_1.0.md).
- [Roadmap](ROADMAP.md), [backlog](BACKLOG_1.0.md), [testes/EVE-NG](TEST_PLAN_1.0.md).
- [Estado verificado](STATUS_REBASELINE_1.0_2026-10-06.md).
