# ADR 0017 — qualificação de backup e restauração v0.6.6

Decisão: testar em CI descartável um par consistente de banco PostgreSQL e store de evidências, com escritores parados. O teste usa a fixture sintética offline da v0.6.5 e os comandos reais `pg_dump`/`pg_restore` do mesmo container do servidor. Não altera o schema nem instala um serviço de backup.

O banco contém projeções e referências; o store contém bundles e receipts originais. Um dump sozinho não recupera a evidência. A cópia deve preservar bytes e caminhos relativos; os comandos de preparação revalidam os hashes após a restauração. A qualificação exige igualdade das 14 tabelas, IDs CAS, findings históricos, catálogo original, eventos de lifecycle, relatório e replays sem mutação.

O harness exige GitHub Actions, opt-in de testes, conexão local, usuário/base `canca_ci` e container hexadecimal informado pelo workflow. Confere a identidade do cluster via SQL dentro e fora do container antes de qualquer DDL. Recusa a base de destino já existente. O schema da origem é reiniciado exclusivamente nesse ambiente descartável; esse script não é um roteiro para o LAB.

A restauração usa base nova criada a partir de `template0`, formato custom, transação única e parada no primeiro erro. Ownership e grants não são restaurados nesta fixture de um único usuário sintético. Qualificação de usuários, privilégios, segredos, certificados e configuração da API requer outra etapa. Dumps e stores temporários não são publicados como artefatos; o log registra hashes e resultados.

Limites: cópia com escritores ativos não é qualificada; não há snapshot atômico distribuído, PITR, HA, agendamento, retenção, criptografia ou recuperação de desastre do ambiente completo. O teste prova a recuperação lógica na mesma versão major, em fixture pequena, e não estabelece RPO/RTO de produção.

Referências: [pg_dump 17](https://www.postgresql.org/docs/17/app-pgdump.html), [pg_restore 17](https://www.postgresql.org/docs/17/app-pgrestore.html), [roteiro LAB R1](LAB_POSTGRESQL_R1_v0.6.5.md).
