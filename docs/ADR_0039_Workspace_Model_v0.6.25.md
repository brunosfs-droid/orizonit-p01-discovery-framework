# ADR 0039 — histórico, grafo e reconciliação por workspace

Data: 07/10/2026. Status: implementado como CANDIDATE opt-in na PR #135.
Abrange o backend dos alvos v0.6.23–25; não encerra R03/R04/R05 nem a Alpha.

## Decisão

A migração 0007 acrescenta objetos, coletas importadas, observações, sinais,
declarações, eventos de relações, planos de import e recibos de requests. Toda
chave de conteúdo inclui workspace_id; referências de site, ambiente, objetos e
relações usam FKs compostas. Tabelas de histórico são append-only para atores da
aplicação, com FORCE RLS. O inventário legado e os bytes de evidência permanecem
intactos. Migrações antigas mantêm seu checksum; o schema7 é opt-in explícito.

Observado e declarado coexistem. A declaração não substitui evidência, e uma
retração manual mantém seu histórico. A identidade automática exige sinal forte
qualificado e corroboração independente; IP/nome isolado não funde dispositivos.
Um vínculo manual registra motivo e só produz sinais elegíveis para correlação
futura quando a evidência satisfaz a política conservadora.

Prévia fixa revisão, política, payload e decisões. Aplicação é transacional,
rejeita drift e review pendente e grava recibo idempotente. Uma revisão de conteúdo
é incrementada pelo banco uma vez por transação, inclusive em INSERT SQL direto;
a criação de planos não altera essa revisão. Campos ausentes preservam evidência
anterior. Nesta versão o adapter observado aceita apenas a categoria identity;
compute/rede/AD são extensões futuras, sem simular cobertura.

## Fence e fronteira de confiança

O token privado combina workspace/generation/lease. Helpers SECURITY DEFINER com
search_path fixo consultam grants da role efetiva, estado open e lock real da
sessão dedicada; não confiam somente no GUC recebido. As funções privadas têm
EXECUTE revogado de PUBLIC. A role efetiva vem do mecanismo SET ROLE verificado
pelo PostgreSQL, não de um campo livre da requisição.

O fence trava a linha de runtime durante a transação. Close/recovery espera um
commit em andamento; perda da sessão detectada antes da saída reverte a gravação.
Cada operação do WorkspaceService registra um job, revalida antes do trabalho e
antes da entrega. Se o commit terminou e depois a entrega foi cancelada, o recibo
permite consulta/replay; uma resposta perdida não prova que nada foi gravado.

DB maintenance e configuração do serviço são confiáveis. O owner dos helpers
precisa de bypass para as leituras internas protegidas; os atores e a role do
coordenador continuam NOSUPERUSER/NOBYPASSRLS. Roles de escrita SQL são identidades
internas da aplicação: RLS não comprova autenticidade de uma projeção forjada por
alguém que detenha essa credencial. O adapter verifica a fonte original e não
aceita payload de observação, path, DSN ou role livres de um cliente.

## Consequências e limites

O grafo é manual e limitado, com origem declared e eventos de remoção sem apagar
histórico. Serviços/relações não comprovam disponibilidade nem executam ações.
A idade observada usa recebimento do import, não horário de coleta autenticado.
Imports evidence_only são históricos sem objetos ativos; promoção de uma coleta
já registrada para outra política ainda não é suportada.

Ainda faltam migração/backfill completo, API/autenticação humana, UI/Mapper,
integração dos jobs e reports legados, observed adapters adicionais, restore7,
benchmarks e LAB/EVE-NG. Nenhum scan ou upgrade operacional é disparado.
[Contrato](WORKSPACE_MODEL_v0.6.25.md) · [Plano](IMPLEMENTATION_PLAN_1.0.md).
