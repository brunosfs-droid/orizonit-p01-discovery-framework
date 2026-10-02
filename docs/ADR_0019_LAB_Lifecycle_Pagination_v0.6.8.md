# ADR 0019 — validação lifecycle e paginação na recuperação R1

02/10/2026. Recuperação R1 v0.6.7 aceita no Rocky; os estados administrativos e cursor/fence ainda precisam de evidência no host.

Adicionar helper independente v0.6.8 aos módulos originais v0.6.5 preservados. CLI permite somente canca_p01_restore_r1;
assessment, actor e request IDs são constantes da fixture. inspect só lê. exercise exige --ack-lifecycle-test
e aplica registered→active→review_required→active→completed na base recuperada. Nenhum DDL, migração,
reindexação, coleta, instalação de serviço ou operação na base origem.

Antes de escrever, comparar com o snapshot original de recuperação: bytes/projeções e 12 tabelas devem
permanecer iguais. Assessments/events são os únicos fingerprints permitidos a mudar, sob validação estrita
de estado/revisão e histórico como prefixo da sequência. História diferente bloqueia a execução sem reparar.
Cada transição usa a API canônica transacional; uma interrupção preserva commits já feitos. Reexecução valida
o prefixo e continua, usando os mesmos request IDs, sem repetir eventos. Um erro não desfaz commits anteriores.

Paginação do relatório em quatro páginas de uma avaliação com scope SHA obrigatório; comparar com consulta
completa, ordenar/deduplicar e exigir fim vazio. Cada transição deve invalidar o cursor anterior.
Depois: replay das quatro requests, três negações esperadas e quatro páginas do histórico; findings continuam
Open. Captura final comprova store/projeções/12 tabelas sem mudança; proof e sidecar privados novos. A CLI recusa saída dentro do store antes da conexão.

Retomada de completed não reaplica decisões e não afirma novo teste de invalidar cursor (contador zero).
Evidência da primeira execução ou da execução interrompida é necessária para esse gate. Estado completed
continua administrativo, sem provar cobertura/segurança/remediação. actor_ref não é identidade autenticada.

Qualificar boundary e DB real PostgreSQL 16/17 antes do LAB. Testes descartáveis podem apagar schema CI;
helper LAB não tem esse comportamento. Sem alterar módulos de produto/SQL existentes ou o hash do engine.
Assumir par quiescente; hashes são comparação de integridade, sem snapshot distribuído ou proteção contra DBA.
Owner do LAB é usado aqui; roles de escrita separadas e TLS remoto permanecem gates próprios.
