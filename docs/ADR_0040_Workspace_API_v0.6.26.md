# ADR 0040 — API humana por workspace

Data: 07/10/2026. CANDIDATE opt-in; listener separado do operador legado.

## Decisão

Reutilizar LocalAuth qualificado para login humano e sessões opacas, com política
imutável de contas. Acrescentar binding privado operador → role SQL, único e
explícito. Grants de assessment não se convertem em grants de workspace.
A configuração contém também a role dedicada do coordenador e raízes de source
por base; nenhum desses campos é escolhido em requests.

O broker SQL abre uma conexão nova por request e assume somente a role configurada.
Broker/atores/coordenador não podem ser SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB.
Atores não podem ser membros do coordenador nem de roles privilegiadas. O broker
é credencial interna confiável, com SET ROLE nas identidades provisionadas; nunca
é entregue ao operador. Acesso/grants reais são revalidados no PostgreSQL.

Cada chamada identifica a base e generation. Token/lease fica interno. A API usa
WorkspaceService para inventário, histórico, grafo, declarações e imports, com
fences SQL/coordenador. Registro de bases não carrega seu inventário. Close rejeita
geração antiga e drena jobs; outra base não abre enquanto houver trabalho pendente.
A criação de workspace/site e alteração de grants continuam manutenção controlada;
esta API não concede administração do servidor a um writer de conteúdo.

## HTTP e sessões

Listener opt-in IPv4 loopback sem TLS, remoto somente com certificado/chave e TLS
1.2+. Host/Origin/Sec-Fetch-Site são verificados como no Web legado, sem confiança
em forwarded headers. Bearer em Authorization, sem cookie/CORS/token em query.
Oito workers, timeout de socket, JSON e queries estritos, corpo128KiB, respostas
limitadas/no-store/CSP, erros fixos e sem logs de payload/credencial.

Sessão é revalidada antes da conexão, antes do trabalho e antes de devolver seu
resultado. Logout/expiração concorrente pode suprimir resposta depois do commit;
isso não equivale a rollback SQL. Request/replay e generation permitem reconciliar
mutações já confirmadas. Revogação de grant permanece controle SQL em cada scope.
Não há refresh, revogação entre processos ou política humana hot reload.

## Limites

API não integra reports/export/scan legados nem oferece UI/Mapper, criação online
de bases/sites, administração/backup, audit HTTP específico de workspace ou ação
em dispositivos. Autor da declaração é role SQL, ligada univocamente ao operador;
recibos/histórico permanecem imutáveis. Alpha/R06 dependem de migração, restore e
integrações futuras. [Contrato](WORKSPACE_API_v0.6.26.md).
