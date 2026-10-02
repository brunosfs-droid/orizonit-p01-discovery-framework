# Cancã — status v0.6.7

Helper de verificação de recuperação **CANDIDATE para LAB**. Sem migração nova, rede de coleta ou alteração da API. Capture e verify leem as 14 tabelas em transação read-only e revalidam as fontes/projeções da fixture R1; captura salva hashes em diretório novo privado. Verify rejeita diferenças sem reparar dados.

R1 básico v0.6.5: **LAB VALIDATED no escopo sintético** no Rocky/PostgreSQL 16.15, por 18 capturas. Import/assets/findings/reader passaram, UPDATE negado esperado; instalação não está mais pendente. [Aceite](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md).

Validação v0.6.7: três testes de boundary e seis casos de PostgreSQL real (incluindo preservação do engine CRLF original), mais integração do helper no smoke de dump/restore 16/17. Logs/head exatos serão registrados na entrega. Ownership/grants, TLS remoto, lifecycle/paginação completos e recuperação operacional no Rocky continuam gates próprios.

[ADR 0018](ADR_0018_LAB_Recovery_Check_v0.6.7.md) · [Roteiro](LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md).
