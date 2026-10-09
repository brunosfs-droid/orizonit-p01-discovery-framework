# Cancã v0.6.41 — R02: preview de intenção de scanner sem execução

**Status:** candidate/PR draft. Base: v0.6.40 integrada na `main` via PR #151, commit
`c606464483b0a7bf7b9259507476a41584569381`.

## O que implementa

O servidor passa a oferecer um método **interno**, opt-in, chamado
`WorkspaceService.live_scan_intent(actor, token, scope_id, mode, ack_authorized_access=True)`.
Ele está subordinado ao coordenador e exige o grant `workspace:write`. Antes e
depois da avaliação da política, revalida lease, generation e autorização.

`ApprovedScopes` é uma configuração privada/imutável por workspace e escopo.
Contém somente redes IPv4 explícitas sob RFC1918, com CIDRs canônicos e
host máximo de 256 endereços utilizáveis em blocos /24 a /32. Redes
sobrepostas, públicas, IPv6, links locais, host bits inválidos, escopos
duplicados e campos inesperados/credenciais são recusados antes de qualquer
operação. O operador só seleciona uma entrada existente, nunca propõe
rede, caminho, senha, comando ou executor.

O resultado retorna exclusivamente um SHA256 de prévia vinculada a workspace,
generation, lease, scope e modo, bem como contagens de redes/hosts e gates
pendentes. Não inclui CIDRs, tokens, caminhos ou credenciais. **SHA256 não é
uma assinatura**; não é aceite operacional nem prova de autorização futura.

As opções `auth_only` e `full_enrichment` apenas descrevem intenções.
`execution_authorized=false` e `status=preview_only` são invariantes.
O método não é registrado no HTTP, não cria jobs persistentes nem acessa os
scanners. Nenhuma rede, autenticação ou alteração de filesystem é executada.

## Gates R02 ainda abertos

- Registro imutável/autorizado da aprovação operacional, com TTL e vínculo ao
  operador e ao job efetivo.
- Secret provider e isolamento de credenciais, política para SSH/WinRM/SNMP.
- Sandbox e encerramento comprovado de processos filhos no Windows/serviços
  remotos, além do POSIX atual.
- Executor AUTH/FULL somente após controles e gates de segurança acima,
  cancellation/checkpoints com transações, replay e observabilidade.
- Escala T14 e homologação de scanner real no EVE-NG.

## Qualificação

`tests/test_workspace_live_intent.py` cobre validações positivas e negativas
de redes e modos, políticas imutáveis, digest preso à generation/lease,
revogação, cross-workspace, falta de acknowledgement e garantia de nenhum
scanner executado. A suíte é incorporada ao Workspace Foundation CI PG16/17
e ao Python CI. R02 e a Product Alpha permanecem **parciais** mesmo se
todos os workflows passarem.
