# Cancã — backup e restauração v0.6.6 CANDIDATE

Qualificação automática do par banco/store em ambiente CI sintético descartável. [ADR 0017](ADR_0017_Backup_Restore_v0.6.6.md). Nenhuma migração nova ou mudança no comportamento da API.

## Cenário

1. Fixture offline com duas coletas WinRM (positiva e negativa), 2 imports, 1 asset CAS, 2 observações, 4 avaliações e 2 findings `Open`.
2. Lifecycle registrado → ativo → concluído, com dois eventos. A conclusão administrativa mantém os findings históricos.
3. Sem escritores concorrentes, dump custom usando `pg_dump` do container PostgreSQL e cópia integral do store; inventário SHA256 antes/depois.
4. Base de destino nova `canca_ci_restore` criada de `template0`. `pg_restore` em transação única com parada em erro, sem owner/grants.
5. Comparação de todas as linhas das 14 tabelas, relatório (excluindo apenas timestamp do snapshot) e schema/checksums de migração.
6. Revalidação dos bundles/receipts do store restaurado com os módulos reais de import/assets/findings, igualdade das projeções e replay sem mutação. Replay do evento de conclusão preserva o evento original.
7. Alteração temporária de receipt é rejeitada por integridade; bytes são repostos e todo o inventário conferido.

## Execução

O workflow [PostgreSQL CI](../.github/workflows/postgres-ci.yml) roda o harness em PostgreSQL 16 e 17 após a suíte de transações. O script `tests/postgres_backup_restore_smoke.py` exige GitHub Actions, opt-in, base/usuário `canca_ci`, host loopback e ID hexadecimal do serviço. Confere a identidade do cluster antes de DDL e recusa destino existente. Ele reinicia o schema da origem CI e **não deve ser executado no LAB**.

O resumo `POSTGRESQL BACKUP RESTORE PASS` informa versão do servidor, 14 tabelas, contagens, hashes do dump/inventário/snapshot lógico, revalidação/replay e tempo observado. Dumps e evidências temporários não são retidos. Não são registrados segredo, linhas das tabelas ou corpo da evidência.

## Limites e LAB

É uma prova de recuperação lógica com escritores parados, na mesma versão major, com fixture pequena. A restauração dos privilégios, usuários, certificados, configuração da API e segredos não é qualificada. Ainda não há backup agendado, política de retenção, PITR, HA, RPO/RTO de produção nem proteção para cópia concorrente do banco/store.

O diagnóstico do Rocky já foi recebido. O gate inicial permanece nas etapas 1–3 do [roteiro LAB R1 v0.6.5](LAB_POSTGRESQL_R1_v0.6.5.md). Não altere o store `/root/p01/store-v05e-r1` ou execute o harness destrutivo CI no Rocky. O roteiro utiliza base e store de fixture separados; recuperação operacional no LAB seguirá após instalação e validação básica.
