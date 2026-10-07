# Cancã MVP 1.0 — workspace e inteligência de infraestrutura

Rebaseline 06/10/2026 (-03). [Especificação completa](PRODUCT_SPEC_1.0.md).
Substitui a classificação anterior post-1.0 de inventário/Mapper/dependências.

## Valor obrigatório

Autorizar → coletar → verificar → reconciliar por workspace → modelar objetos/
relações → avaliar → explicar → Mapper/serviços/reports → planejar ações.
Recomendações e candidatos a mudança; sem remediação automática.

## Dentro da 1.0

- Vários workspaces isolados armazenados, um aberto por instalação; sites internos
  e ambientes lógicos opcionais, grants, carga/close/recovery e caches limitados.
- Standalone/Node e scans via servidor com autorização, SSH/WinRM/SNMP read-only,
  Secret Provider, evidência/bundle, offline import e outbound mTLS preservados.
- CollectionRun/Observation/Declaration/AssetIdentity/Relationship e migração.
- Wizard com prévia/diff/categorias/revisão/idempotência, histórico e estado atual.
- UI orientada a workspace/páginas de objetos, Mapper central/submapas/zoom/camadas,
  objetos manuais/passivos e desenho de serviços/dependências/impacto potencial.
- Redes/AD/Windows/Linux/virtualização/M365, findings explicáveis e catálogos/MIBs/
  ícones/firmware/patch conforme matriz e qualificações da especificação.
- Dashboards/reports técnicos/executivos/customizados, ações/horizontes e mudança.
- Administração separada, backup servidor/workspace, restore/upgrade/instalação/docs.

## Fora da 1.0

NMS contínuo, simulação de pacotes, exploração, patch deployment/remediação,
CMDB/IPAM enterprise completos, dependência totalmente automática, autoridade AI,
SaaS público multi-tenant, billing/marketplace e comandos remotos arbitrários.

## Gates de qualidade

Isolamento SQL/API/store/jobs/exports; sem secrets em evidência; sem spraying/
merge por IP; proveniência/cobertura/unknown/conflitos; integridade/replay offline
connected; Node mTLS; migração/grants/recovery qualificados; consultas limitadas;
instalação reproduzível, SBOM/licenças/matriz pública e limitações antes da Beta.

## Estado real

Primeiro incremento workspace [v0.6.21 CANDIDATE](WORKSPACE_FOUNDATION_v0.6.21.md):
registry/grants/sites/ambientes e mapping opt-in em base isolada. Migração completa,
[v0.6.22](WORKSPACE_COORDINATOR_v0.6.22.md) adiciona coordenador lógico de carga
única; API/Mapper/loader/jobs legados ainda pendentes. Contratos legados v0.6.20/SNMP v0.4b.9
preservados.
Distributed mTLS R2 e R1 sintéticos PostgreSQL/recovery/lifecycle/CLI export/API/Web
já têm aceite nos escopos registrados. Download Web v0.6.13+ e incrementos
posteriores, vendors reais e roles/TLS/produção mantêm seus gates pendentes.
Scheduler R1/soak curto aceitos; multi-day/live é distinto. Não repetir gates
aceitos sem mudança relevante; nenhuma validação humana solicitada neste turno.

A Alpha não está encerrada: implementar/qualificar os fundamentos R01–R06 antes
v0.7. [Roadmap](ROADMAP.md), [plano](IMPLEMENTATION_PLAN_1.0.md),
[testes](TEST_PLAN_1.0.md), [estado verificado](STATUS_REBASELINE_1.0_2026-10-06.md).

## Community e maturidade

Apache-2.0, Community estável primeiro. Fluxo central de workspace/Mapper/assessment
útil na Community; cotas/profundidade comercial exatas ainda não definidas.
Nenhum enforcement/licensing server introduzido nesta revisão.
Beta exige instalação/security/contribuição/CLA/code of conduct/release process,
SBOM/licenças/matriz/known limitations e backup básico. RC congela features e
qualifica upgrade/restore; GA fecha bloqueadores e publica suporte real.
