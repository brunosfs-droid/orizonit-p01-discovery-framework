# Cancã — Workspace HTTP Audit v0.6.29

Status: **CANDIDATE opt-in**, schema9 preservado. Este incremento não altera
tabelas, migrações, stores, grants SQL, reconciliação ou relatórios históricos.

## Objetivo

O listener humano de workspace pode registrar uma trilha JSONL privada das
requisições HTTP admitidas. A auditoria cobre login/logout, diretório de workspaces,
open/close, objetos/grafo, declarações/relações, import preview/apply,
legacy preview/apply e relatório histórico. O default continua sem arquivo de
auditoria.

Exemplo estrutural:

```sh
python server/P01_Workspace_API.py \
  --accounts /private/accounts.json \
  --bindings /private/workspace-bindings.json \
  --audit-file /private/workspace-audit/run-001.jsonl
```

O arquivo precisa ser novo, privado e exclusivo. Em POSIX, o diretório não pode
conceder acesso a group/other e o arquivo nasce 0600; symlink, reparse point,
hardlink, alias e reutilização de arquivo existente são recusados. Windows exige
ACL de implantação restritiva própria; mode POSIX não prova essa ACL.

## Registro e redação

Cada request admitido possui `request_started` e `request_finished`, com
`sequence`, timestamp UTC, `operation` e `request_id` aleatório do servidor.
O término registra somente `http_status`, `outcome`, `operator_id` e
`workspace_id` já confiáveis.

`workspace_id` só é publicado depois que a operação do workspace retorna com
sucesso. Uma tentativa negada não copia o ID arbitrário enviado pelo cliente.

Nunca são copiados username submetido, senha, bearer/token/hash, headers, body,
query, cursor, generation, revision, request_id do cliente, IDs de objeto,
relationship, plan, bundle ou assessment, scope hashes, paths, DSN, erros brutos,
relatório ou evidência.

As operações possíveis são rótulos fixos: login/logout/health, diretório e
lifecycle do workspace, leituras de objeto/grafo, alterações manuais,
preview/apply de import, preview/apply do legado e relatório histórico.
A rota e a query originais nunca são gravadas.

## Falha fechada e limites

O orçamento máximo é 8 MiB por execução, com até oito requests ativos e reserva
para finalizar requests já admitidos e `listener_stopped`. Não há append,
rotação, purge, compressão ou reparo live. Alteração externa do arquivo/diretório,
falha de fsync, capacidade esgotada ou inconsistência de identidade invalida o
sink.

Quando `begin` falha, a nova requisição recebe 503
`workspace_audit_unavailable` antes de login/logout/SQL/serviço. Uma falha em
`finish` pode ocorrer depois da resposta e não desfaz uma mutação já commitada;
o sink permanece inválido e novas admissões falham.

Encerramento normal aguarda workers e fecha o arquivo. Interrupção abrupta pode
deixar prefixo incompleto; esse arquivo deve ser preservado e nunca reutilizado.

## Limites do gate

Isto não é log imutável, assinatura, SIEM, retenção, HA ou prova de autoria.
Handshake/TLS recusado, erro anterior ao handler, saturação anterior ao worker e
logs do SO/proxy pertencem a gates operacionais separados.

O contrato v0.6.28 permanece pinado: schema9, backfill revisado, relatórios
históricos e restores schema8/9 não são modificados por este incremento.
Migração/readers adicionais e recovery operacional continuam gates separados
para fechamento de R06/Alpha.

[ADR 0043](ADR_0043_Workspace_HTTP_Audit_v0.6.29.md).
