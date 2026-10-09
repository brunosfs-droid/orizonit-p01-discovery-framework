# Cancã v0.6.43 — preview de escopo de varredura via HTTP autenticado e auditado

**Candidato R02**, empilhado sobre v0.6.42/PR #153. Nenhuma coleta, AUTH,
FULL, credencial, export ou upload é executada nesta versão.

## O que foi acrescentado

`POST /api/v1/workspaces/{workspace_id}/scan-intents/preview` recebe somente
`generation` (integer), `scope_id` (identificador da política privada),
`mode` (`auth_only` ou `full_enrichment`) e
`ack_authorized_access: true`. Qualquer campo extra, incluindo targets,
password, commands ou credentials, falha com HTTP 400. Query string, GET e
paths arbitrários não são permitidos.

O endpoint depende do arquivo de `BindingPolicy` privado, cuja configuração
opcional `approved_scan_scopes` é validada pelo mesmo `ApprovedScopes`
da v0.6.41. Quando ausente, a política está vazia e o acesso é negado.
Nenhum CIDR vem da requisição HTTP. A configuração é imutável em runtime;
permissões são verificadas por identidade SQL e grant `workspace:write`,
coordenador, geração e lease ativo.

A chamada só é habilitada quando o listener possui o
`P01_Workspace_Audit.FileAudit` privado. Sem trilha de auditoria:
HTTP 503 fail-closed, antes do método de serviço. A operação é registrada
como rótulo constante `scan_intent_preview`, com metadados fixos de
operador/workspace e sem CIDR, scope, query, digest ou secrets. O audit file
existente é configurado em modo opt-in pelo operador do servidor.

**Resposta:** `status: preview_only`, `execution_authorized: false`,
contagens e digest contextual com lease, workspace, geração, escopo e modo.
O SHA256 é vinculação de dados da prévia, **não** autorização assinada
para execução. A resposta não contém os CIDRs. O endpoint não expõe os
comprovantes efêmeros v0.6.42 nem concede quaisquer permissões adicionais.

## Testes

- HTTP 503 sem FileAudit; 200 somente quando audit privado habilitado.
- Erros 400 com query, senha, alvo, modo não conhecido, falta de consentimento
  explícito, geração não inteira e campo adicional.
- Sessões não autenticadas ou revogadas devem retornar 401.
- Operação da auditoria é classificada sem copiar dados da rota.
- Binding de escopos rejeita redes públicas, CIDRs não explícitos e campos
  de credenciais; configuração é imutável.
- Python CI, PostgreSQL 16/17 Workspace Foundation CI, CodeQL e demais
  workflows obrigatórios do **último commit**.

## Bloqueios que permanecem

Produto Alpha R02 e R06 continuam parciais. O caminho AUTH/FULL real exige
ledger durável de aprovação com identidade do aprovador, custódia/rotação
de secrets, perímetro sandbox, contenção de processos Windows e remotos,
interruptibilidade durante I/O e comprovação no EVE-NG. A aprovação desta
PR não constitui homologação da execução de scanners.
