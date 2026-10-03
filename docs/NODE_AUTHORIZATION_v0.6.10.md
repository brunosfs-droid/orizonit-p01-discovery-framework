# Cancã — autorização explícita de Discovery Nodes v0.6.10

**CANDIDATE.** A API de ingestão pode restringir envio e consulta de bundles por
Discovery Node e assessment. A identidade vem do certificado mTLS verificado,
mantendo a correspondência com `X-P01-Node-ID` e o `node_id` do bundle/recibo.

## Política

Copie [o exemplo sintético](../ingestion/node-policy.example.json) para uma área
de configuração controlada pelo administrador, fora do store. Defina os IDs
reais apenas no arquivo local. Não publique inventários de clientes no Git.

| Campo | Regra |
| --- | --- |
| `policy_version` | String `"1"` |
| `nodes` | Até 128 entradas; lista vazia nega todos os nodes |
| `node_id` | ID certificado; comparação sem diferenciar maiúsculas/minúsculas |
| `grants` | Até 128 assessments por node; lista vazia não concede operações |
| `assessment_id` | Correspondência exata, inclusive maiúsculas/minúsculas |
| `permissions` | `bundle:ingest` e/ou `bundle:read`; lista vazia nega operações |

IDs usam 1–128 caracteres ASCII: primeiro alfanumérico, demais alfanuméricos,
ponto, hífen ou underscore. Não há wildcard nem sanitização de IDs. Campos,
chaves JSON, nodes ou grants duplicados, permissões desconhecidas e arquivos
inválidos abortam startup. O arquivo regular tem limite de 64 KiB. Em sistemas
com `O_NOFOLLOW`, aliases por symlink são rejeitados. Configure permissões locais
para que apenas administradores possam substituir a política.

## Habilitar em uma implantação de teste nova

Acrescente `--node-policy /caminho/controlado/node-policy.json` ao comando de
ingestão mTLS existente, junto de `--transport-mode mtls`, `--tls-cert`,
`--tls-key` e `--client-ca`. Não é aceito no transporte localhost.
O arquivo completo é validado antes de criar o store ou abrir o servidor.
Não há migração nem conexão ao banco para carregar a política.

O `/healthz` retorna `authorization_mode: node_policy` quando habilitada e
`transport_only` quando ausente. O segundo modo preserva compatibilidade, mas
não limita assessments: deployments que precisam de isolamento devem habilitar
a política. O health não enumera grants. O hash SHA256 da configuração fica
disponível apenas no objeto local da política, sem conteúdo no output HTTP.

## Comportamento esperado

- Sem identidade autenticada: 401. Node ausente: 403 antes de consumir o upload.
- Assessment ou operação sem grant: 403 antes do importer/indexador.
- Grant de ingestão não concede consulta; grant de consulta não concede ingestão.
- Consulta ainda exige propriedade do bundle pelo node, além do grant.
- mTLS/certificado/header/manifest incompatíveis continuam bloqueados.
- Erros de autorização têm mensagens fixas; grants e arquivo não são retornados.
- Rejeição antes de consumir o body fecha a conexão HTTP.
- Permissão de leitura é verificada antes de retornar recibo/consultar PostgreSQL.

## Alteração e revogação

A política é um snapshot imutável carregado no startup. Editar o arquivo não
muda um processo existente. Para remover acesso, faça restart controlado com
a nova política, sem escritores/requests pendentes; conexões do processo antigo
devem terminar antes de admitir tráfego no novo processo. Não há hot reload,
revogação imediata nem cancelamento de requests já autorizados neste incremento.

## Limites e próxima etapa

Este principal representa um Discovery Node, não um usuário. CLI e importação
offline continuam sob permissões do host. Não implementa tenancy, autenticação
de operador/Web, RBAC de usuários, enrollment, audit persistente ou comandos
remotos. Essas fronteiras terão decisões e testes próprios. Os gates Rocky do
exportador, roles completos e TLS remoto PostgreSQL continuam independentes.

[ADR 0022](ADR_0022_Node_Assessment_Authorization_v0.6.10.md).
