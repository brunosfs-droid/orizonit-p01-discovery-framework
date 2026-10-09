# Cancã v0.6.39 — primeiro fence de subprocesso legado (R02)

CANDIDATE. Implementa exclusivamente um checkpoint read-only do runtime
`P01_Discovery_Node.py status --json`, executado como subprocesso fixo e
registrado no coordenador de workspace. Não é coleta, enriquecimento ou upload.

O backend `WorkspaceService.legacy_checkpoint` usa `workspace:read`, token
de workspace e generation correntes. A configuração privada mapeia workspace
a um diretório de execução legado já existente. O cliente **não** fornece
argumentos de subprocesso, path, credenciais, alvo, rede ou executor arbitrário.
O processo não recebe shell, stdin, stdout/stderr publicados ou resultados em
cache. Em fechamento/troca/perda de lease, o job recebe cancelamento, termina
o subprocesso e suprime a entrega; timeout também termina. Readiness e
`check` após saída validam autorização/contexto. Sem alteração de schema.

Este é um gate interno/opt-in: não há rota HTTP nem configuração de usuário
publicada. O subprocesso em si usa apenas `status`; `run`, `execute`,
AUTH/FULL, `upload` e scanners não estão liberados. O modelo de subprocesso
ainda não prova cancelamento de árvores de processos nem interrupção de I/O
real de scanners. R02/T03 e T14 permanecem parciais.

Testes: saída exit0, saída não zero redigida, timeout, fechamento concorrente,
token antigo, grant revogado, roots incorretas e nenhum subprocesso após
falha de pré-condição. Requer Python CI e Workspace Foundation PG16/17 no
último commit, depois LAB autorizado para integração ativa. A aprovação
automática não qualifica nenhum scanner/vendor.
