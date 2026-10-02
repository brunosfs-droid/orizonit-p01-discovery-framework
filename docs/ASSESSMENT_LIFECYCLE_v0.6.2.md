# Assessment lifecycle — v0.6.2

**CANDIDATE para LAB**, 02/10/2026 (-03). PostgreSQL 16/17; CLI administrativa
separada. [Decisão](ADR_0013_Assessment_Lifecycle_v0.6.2.md).

## Significado dos estados

| Estado | Significado |
| --- | --- |
| registered | Identificador registrado; nenhuma decisão de início ou conclusão |
| active | Operador declarou o assessment em andamento |
| review_required | Operador interrompeu o avanço administrativo para revisão |
| completed | Operador declarou encerramento administrativo |
| cancelled | Operador cancelou o assessment |

`registered → active → completed` é o caminho direto. `active → review_required
→ active` registra revisão e retomada. Os três estados não terminais permitem
`cancelled`. `completed` e `cancelled` não permitem reabertura. A revisão precisa
ser retomada para `active` antes de completar.

Esses estados não acionam nem suspendem discovery, scheduler, AUTH, FULL ou POST.
`completed` não garante coleta integral, cobertura do escopo, qualidade das
evidências ou que todos os imports estejam indexados. Essa decisão pertence ao
operador. Um import posterior pode ser indexado sem alterar o estado terminal.

## Preparação do banco isolado

Use as dependências e configuração explícita `PGHOST/PGDATABASE/PGUSER` do
[guia PostgreSQL](../persistence/README.md), com credenciais externas à CLI e TLS
remoto `verify-full`. Ainda não é um roteiro de instalação no P01LAB.

Antes de adotar o novo schema, preserve backup da base e o binário correspondente.
Com a conta de DDL, a migração explícita aplica 0001 e 0002 ou apenas 0002 em uma
base existente com 0001 válida:

```sh
python persistence/P01_PostgreSQL.py migrate
```

Retorna `migration: 2`; replay `already_migrated`. A transação preserva dados de
imports e registra SHA256 de cada SQL. Assessments existentes tornam-se
`registered`, revisão 0, sem eventos inventados. Migração falha inteiramente se
checksum/seqüência divergir ou houver conflito de DDL. Não há migração no startup
da API. O código novo de índice tolera schema 1; lifecycle exige schema 2.
Binário antigo que espera somente 0001 rejeita schema 2. Não existe downgrade;
restauração requer backup/restore com o binário compatível.

## Operação explícita

Exemplo em base sintética dedicada, substituindo IDs pelas referências corretas:

```sh
python persistence/P01_Assessment_Lifecycle.py register --assessment-id LAB-001
python persistence/P01_Assessment_Lifecycle.py show --assessment-id LAB-001
python persistence/P01_Assessment_Lifecycle.py transition --assessment-id LAB-001 --expected-revision 0 --request-id LAB-001-start-01 --target-state active --actor-ref operator-01
python persistence/P01_Assessment_Lifecycle.py transition --assessment-id LAB-001 --expected-revision 1 --request-id LAB-001-review-01 --target-state review_required --actor-ref operator-01
python persistence/P01_Assessment_Lifecycle.py transition --assessment-id LAB-001 --expected-revision 2 --request-id LAB-001-resume-01 --target-state active --actor-ref operator-01
python persistence/P01_Assessment_Lifecycle.py transition --assessment-id LAB-001 --expected-revision 3 --request-id LAB-001-finish-01 --target-state completed --actor-ref operator-01
```

Registro idempotente: `registered` ou `already_registered`, sem reset. Um import
também pode criar o registro neutro. `show` retorna `found` ou `not_found` e não
cria registros. Histórico paginado: `--after-revision N --limit 1..100`; seguir
`next_after_revision` enquanto `has_more`. Estado/revisão e página vêm de um único
snapshot de leitura. Consultas sucessivas podem observar mudanças posteriores.

Cada transição aceita somente a revisão observada. `applied` retorna o evento
persistido, com revisão, request ID, origem/destino, código fixo e timestamp UTC.
Use o mesmo request ID e o mesmo payload para repetir uma operação cuja resposta
se perdeu: `already_applied` devolve o evento original, mesmo que o assessment já
tenha avançado. Esse recibo histórico não é o estado corrente; consulte `show`.
IDs são únicos por assessment e nunca devem ser reutilizados para outra decisão.

| Falha | Ação do operador |
| --- | --- |
| revision_conflict | Consultar estado e avaliar a decisão concorrente; não repetir cegamente |
| request_conflict | Preservar o request original; novo ID apenas para uma decisão nova |
| transition_invalid | Revisar a origem e as transições permitidas |
| assessment_not_found | Conferir o ID antes de registrar explicitamente |
| schema_required / schema_mismatch | Conta DDL e revisão de migração, sem reparo automático |
| database_failed | Revisar disponibilidade; repetir com mesmo ID após resolver |

Falhas retornam JSON com código fixo e exit 2. Sucesso e `not_found` retornam exit
0. Estado e evento são atômicos; timeout lock 5s/statement 30s, sem retries.

## Permissões e limites de confiança

A API de ingestão não expõe lifecycle, nem concede esse controle a certificados
de nodes. A CLI usa a conta PostgreSQL configurada pelo operador. `actor_ref` é
referência declarada, não autenticação de usuário; use ID não secreto e mantenha
atribuição/autorização em controles externos. Não informe senhas, nomes de
arquivos, DSN ou evidências nesses IDs.

Uma role operacional pode ter USAGE no schema, SELECT em `schema_migrations`,
`assessments` e `assessment_events`, INSERT somente na coluna `assessment_id` de
`assessments`, UPDATE somente em `lifecycle_state/lifecycle_revision`, e INSERT em
`assessment_events`. Não precisa de DELETE, UPDATE de eventos ou CREATE. Essas
permissões permitem SQL direto; a role deve ser confiável. A aplicação não é RBAC
nem valida identidade de actor_ref, e DBA pode alterar dados. O histórico é
append-only pelo código, sem assinatura criptográfica ou proteção contra DBA.
Permissões do indexador continuam separadas, sem controle de lifecycle.

CI usa base efêmera e dados sintéticos. Roles/TLS/backup/restore em P01LAB,
autenticação de produto, API administrativa e UI continuam gates independentes.
Não habilite `CANCA_TEST_POSTGRES=1` em uma base real: os testes apagam o schema.
