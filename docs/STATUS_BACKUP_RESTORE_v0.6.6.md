# Cancã — status técnico v0.6.6

Status: **CANDIDATE para LAB**, com qualificação de backup/restore sintético em CI PostgreSQL 16/17. A aceitação depende do head exato e dos logs registrados no PR desta versão.

Incremento: recuperação do par banco/store, comparação integral das 14 tabelas e do relatório, revalidação das evidências e replay sem mutações. Um receipt alterado é rejeitado. Nenhuma migration ou funcionalidade da API foi alterada.

Os testes de guarda recusam ambiente fora do CI, base LAB, usuário/host divergente e argumento de container inválido antes de conexão/subprocessos. A qualificação real executa os utilitários no container do servidor, com base destino nova; não reutiliza nem apaga destino existente.

Limites: fixture exclusiva, mesma versão major, ownership/grants não restaurados, sem HA/PITR/retention/encryption ou RPO/RTO de produção. LAB Rocky continua pendente das etapas 1–3 do [R1](LAB_POSTGRESQL_R1_v0.6.5.md). O diagnóstico recebido já está incorporado; não há repetição do soak do agente solicitada.

[Guia](BACKUP_RESTORE_v0.6.6.md) · [ADR 0017](ADR_0017_Backup_Restore_v0.6.6.md) · [Relatório v0.6.5](ASSESSMENT_REPORT_v0.6.5.md).
