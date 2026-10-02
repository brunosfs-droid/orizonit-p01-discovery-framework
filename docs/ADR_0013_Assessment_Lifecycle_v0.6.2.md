# ADR 0013 — Ciclo de vida administrativo do assessment

Data: 02/10/2026 (-03). Status: aceito para implementação CANDIDATE v0.6.2.
Escopo A/MVP; refs #63, ADR 0011 e ADR 0012.

## Problema

O índice PostgreSQL registra assessments a partir de imports, mas não representa
decisões do operador sobre início, revisão e encerramento. Um import bem sucedido
não comprova que todo o escopo foi coletado nem que o assessment está concluído.

## Decisão anterior à implementação

Adicionar a migração explícita 0002, sem modificar 0001. Assessments existentes e
novos recebem `registered`, revisão 0. O backfill não fabrica eventos ou conclusões.
Registro explícito pelo operador também é idempotente. Ingestão continua apenas
criando o registro neutro: imports tardios não reabrem ou encerram assessments.

| Origem | Destinos permitidos |
| --- | --- |
| registered | active, cancelled |
| active | review_required, completed, cancelled |
| review_required | active, cancelled |
| completed | nenhum |
| cancelled | nenhum |

`completed` é uma declaração administrativa explícita do operador, não uma
certificação automática de cobertura, qualidade, ausência de imports pendentes ou
conclusão do runtime. Não impõe coleta, AUTH, FULL, POST, agendamento ou publicação.

Uma CLI administrativa separada utiliza credenciais PostgreSQL do operador; a API
de ingestão e certificados de nodes não recebem controle de lifecycle. Cada mudança
exige assessment, revisão esperada, request ID, destino e referência não secreta do
operador. A referência é declarada, não identidade autenticada pela aplicação;
controle de acesso e atribuição autenticada pertencem às roles/controles externos.

Transação com row lock, revisão otimista e evento único por request ID/assessment:
estado e evento são gravados juntos. Replay idêntico retorna o recibo original,
mesmo depois de outras mudanças; reutilização com payload diferente é conflito.
Revisão obsoleta, transição inválida e assessment inexistente não alteram dados.
Eventos são append-only pela aplicação, com códigos de motivo fixos e sem texto
livre, credenciais, caminhos de arquivos ou payloads de evidência. DBA continua
capaz de modificar o banco; esse histórico não é um journal criptográfico.

Consultas usam snapshot consistente e histórico paginado, sem mutações. A leitura
retorna a revisão corrente separada do recibo histórico de replay.

## Migração e compatibilidade

Sequência e hashes das duas migrações devem corresponder a um prefixo conhecido.
`migrate` aplica apenas o sufixo ausente, atomicamente e sob lock de migração.
Checkout das migrações fixa LF para manter os mesmos bytes/hashes entre hosts.
Indexação/consulta de imports do código novo aceitam esquema 1 ou 2 verificado;
lifecycle exige esquema 2. Startup da API não migra. A nova inserção de assessment
nomeia a coluna, permitindo defaults do esquema 2 sem alterar o índice anterior.
Binários antigos que exigem somente a migração 1 rejeitam o esquema 2. Não há
downgrade destrutivo; restauração exige backup e o binário correspondente.

## Validação e limites

Testar upgrade com dados existentes, hashes/versões desconhecidos, replay após
avanço, concorrência com revisão igual, rollback na inserção do evento, estados
terminais e ausência de conclusão automática na ingestão. CI PostgreSQL 16/17 real
complementa contratos locais; LAB de roles, TLS, backup/restore continua pendente.
RBAC de produto, API administrativa, UI, asset identity e retenção ficam fora deste
incremento. O runtime e o scheduler validados permanecem nas versões anteriores.
