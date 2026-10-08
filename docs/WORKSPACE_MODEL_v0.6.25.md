# Cancã — Workspace Model v0.6.25

CANDIDATE opt-in. Backend aditivo dos alvos v0.6.23–25: histórico, grafo manual e
import revisado, integrado a jobs do coordenador. Não fornece listener HTTP nem
UI/Mapper. [Decisão](ADR_0039_Workspace_Model_v0.6.25.md).

## Contratos programáticos

| Operação | Contrato |
| --- | --- |
| registry | Lista somente workspaces autorizados e ciclo sem expor ID de base sem grant; não carrega inventário. |
| active_token | Workspace/generation explícitos; conexão do mesmo banco e grant atual. Lease permanece interno. |
| declare_object | Revisão esperada, request_id, tipo, label e motivo; atributos tipados; site/ambiente da própria base. |
| declare_attribute | Evento manual com motivo/autor; null retrai a declaração, sem apagar observações. |
| relationship | Evento manual com extremos imutáveis, tipo e motivo; active=false registra remoção. |
| objects / object / graph | Leitura autorizada e fence de geração; revisão opcional para paginação consistente. |
| preview_import | Handle assessment/bundle em diretório configurado do workspace; fonte original verificada; mode/categories/decisões explícitos. |
| apply_import | Plano imutável, revisão ainda atual e request_id; transação e recibo idempotente. |

Objetos: host, device, interface, component, network, vlan, service, group, passive.
VLAN manual exige vlan_id e vlan_namespace. Relações: connected_to, hosted_on,
member_of, depends_on, available_on, located_in. Arestas são declaradas; não há
simulação de impacto, descoberta LLDP ou inferência de redundância nesta etapa.

O SourceRoots é configuração interna, com raízes canônicas existentes e disjuntas.
O cliente fornece IDs, sem escolher path/DSN. A origem tem SHA de bundle/projeção,
assessment/run/node externos e referências de evidência preservadas. Cada base
pode registrar a mesma evidência em seu namespace, sem relacionar objetos entre
bases. Assessment legado não concede permissão automática à base inteira.

## Revisões e falhas

Request idêntico retorna recibo original, com replayed=true; reutilização do ID com
payload diferente gera model_request_conflict. Alteração desde a prévia gera
model_revision_stale; decisões pendentes geram model_review_required. Nova prévia
é necessária após drift. O mesmo bundle já aplicado é imutável: mudança de modo,
seleção ou projeção gera model_import_conflict.

Fechamento cancela jobs e aguarda drenagem. Resultado tardio é rejeitado;
workspace_close_pending mantém closing/lease. Perda de sessão exige recovery;
shutdown agora conclui a limpeza também quando descobre essa perda pela primeira
vez. Commit já concluído pode ter resposta suprimida; utilizar recibo/replay para
reconciliar, nunca inferir rollback a partir de falha de entrega.

## Limites atuais

- Um import: até 1.000 observações e 4 MiB de projeção canônica; categoria identity.
- Objetos: paginação por chave de até 100, com revisão fixável pelo consumidor.
- Objeto: até 100 observações e 100 declarações; exceder retorna model_history_bound.
- Grafo: profundidade 0–4, até 100 nós/200 arestas; truncated sinaliza cortes.
- Identidade: até 100 candidatos/histórico no resolver; ambiguidade vai para revisão.
- Campos declarados: strings limitadas, inteiros de capacidade e VLAN validados,
  CIDR canônico; chaves de segredo não são aceitas.

Não confundir limites de proteção com capacidade comercial ou benchmark. Ausência
numa coleta parcial não remove o objeto/campo anterior. Estado distingue observed,
declared, conflito e desconhecido; time_basis=import_received e
collection_time_known=false evitam apresentar recebimento como coleta comprovada.

## Provisionamento isolado

Somente com o coordenador encerrado e manutenção confiável:

```sh
python persistence/P01_Workspace_Model.py migrate
```

Migração7 rejeita coordenador ativo e não altera prefixos1–6. Atores recebem
SELECT nas tabelas novas e EXECUTE somente em workspace_model_allowed(boolean) e
workspace_revision_lock(boolean). Writer recebe INSERT nas tabelas de conteúdo e
planos/recibos, nunca UPDATE da revisão nem acesso ao runtime. Grants de workspace
continuam explícitos. Aplicação deve usar conexão própria por operação e
WorkspaceService; esse provisionamento ainda não é um instalador automático.

Continuação integrada: [API humana v0.6.26](WORKSPACE_API_v0.6.26.md) e
[recovery isolado schema8 v0.6.27](WORKSPACE_RECOVERY_v0.6.27.md). Backfill e readers
por snapshot continuam pendentes antes de UI workspace/Mapper. O contrato desta
versão permanece em schema7; Windows nativo e dispositivos reais mantêm seus gates.
