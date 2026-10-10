# Cancã v0.6.88 — contrato rígido de semântica e campos E0

## Objetivo

O validador E0 já bloqueia chaves JSON duplicadas (v0.6.87), mas ainda aceitava *campos extras* e descrições arbitrárias para os dez gates. Isso permitia rebatizar um teste obrigatório sem invalidar o registro — uma divergência entre o checklist operacional e a estrutura avaliada automaticamente.

## Contrato implementado

O verificador comum `E0_EVIDENCE_CHECK_v0.6.82.py` agora:

1. Exige exatamente os campos `schema_version`, `release_commit`, `topology_sha256`, `scope_approval_ref`, `operator`, `executed_at_utc`, `security_reviewer`, `release_reviewer` e `gates` na raiz. Campos desconhecidos e omissões produzem **INVALID**.
2. Exige `schema_version` como inteiro literal `1`. Booleano `true`, `1.0` e string `"1"` não são equivalentes.
3. Exige que cada entrada de gate contenha exatamente `gate_id`, `description`, `result`, `evidence_uri`, `evidence_sha256`, `reviewer` e `executed_at_utc`, sem propriedades adicionais.
4. Fixa a descrição de cada E0-01 até E0-10 segundo o registro de referência v0.6.82. Por exemplo, **E0-06** deve continuar `Coordinator cancel/drain/lease (R02)` e **E0-08** `Same-cluster recovery (T13)`. A troca desses textos invalida o registro em vez de reinterpretar silenciosamente o requisito.
5. Rejeita metadados/valores opcionais de tipo inesperado, ainda que o gate esteja em `NOT RUN`. Nulos seguem válidos quando não houve teste ou sign-off.
6. Redige IDs inválidos em diagnósticos inclusive para `FAIL`, `BLOCKED` e `NOT RUN`; utiliza `gate[N]`, não o identificador fornecido.

## Compatibilidade e testes

- O registro JSON padrão v0.6.82 permanece compatível e continua com **dez NOT RUN / NO-GO**.
- Os três CLIs de evidência, integridade de arquivos e snapshot herdam o contrato via validador comum. Nenhuma coleta é executada pelo CI.
- Os testes em `tests/test_e0_evidence_gate.py` exercitam alteração semântica de gate, campos excedentes/ausentes, tipos errados, número de versão ambíguo e redaction.
- Se um dia for necessária uma nova descrição de gate ou campo, exige-se **revisão explícita de contrato e migração versionada**, e não alteração silenciosa do JSON.

## Fora do escopo

O contrato preserva significado e formato do registro; não comprova que a topologia foi testada, que identidades dos revisores foram atestadas ou que o restore cross-cluster funciona. E0/EVE-NG, R02/R06, T13/R20 e homologação da Alpha permanecem pendentes.
