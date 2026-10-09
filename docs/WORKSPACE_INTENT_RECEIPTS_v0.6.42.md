# Cancã v0.6.42 — comprovante transitório de revisão da intenção R02

**Candidato em branch dependente da PR #152. Não habilita execução AUTH/FULL.**

## Objetivo

Acrescentar ao *preview-only* v0.6.41 um comprovante de revisão com TTL
e consumo único, mantendo controle fail-closed por workspace/generation/lease,
scope e modo. Isso permite exercitar fluxo de revisão de escopo sem entregar
uma autorização de execução ou realizar autenticação de dispositivos.

O `ReviewReceipts` é um registro **volátil e em memória**, máximo 64 entradas
por instância (configurável 1–256), TTL 60 segundos (configurável 1–300).
Somente um actor com `workspace:write` e token válido do coordenador pode
registrar ou consumir o comprovante via `WorkspaceService`. O prévio
`scope_digest_sha256` deve corresponder exatamente à configuração privada
corrente, geração, lease e modo. A operação exige reconhecimento explícito.

O método `record_scan_review(...)` retorna um identificador randômico de
48 caracteres hexadecimais. O livro guarda apenas seu SHA256 e atributos
de vínculo, não o identificador em claro. `consume_scan_review(...)` aceita
o mesmo vínculo uma única vez: consumo repetido, expiração, mudança de
workspace/geração, digest diferente, revogação de grant ou modo alterado
são recusados. Nenhuma operação publica redes/CIDRs, credenciais ou comandos.
Os comprovantes não são serializados para disco e não são aceitos por
qualquer executor.

**Importantíssimo:** `review_recorded_only` e `review_consumed_only`
possuem `execution_authorized=false`. Consumo significa somente um teste
da correlação de uma revisão em memória. Não é autorização administrativa,
assinatura digital, auditoria persistente nem mecanismo de permissão para
realizar varreduras. Um restart invalida todos os comprovantes.

## Testes e gates

- Unicidade/consumo único, expiração, reciclagem de capacidade.
- Alteração de modo, hash incorreto, token velho e troca A↔B.
- Revogação de `workspace:write` antes do consumo.
- Entradas inválidas, invariantes de ausência de rede/autenticação
  e nenhum chamado ao executor.
- Compilação + `Python CI` e `Workspace Foundation CI` PG16/17,
  além de todos os workflows da PR após o último commit.

## O que ainda impede scanners reais

Para R02 há necessidade de identidade explícita e auditável do aprovador,
ledger **persistente**/imutável, aprovação operacional com TTL e idempotência,
isolation/secret provider, transport/auth policy, Windows process tree
containment, cancelamento em I/O remoto e homologação EVE-NG. Portanto,
R02 e a Product Alpha continuam **PARCIAIS**, independentemente do resultado
destes testes. R04/R05 e recuperação operacional R06 permanecem separados.
