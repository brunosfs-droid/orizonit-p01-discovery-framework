# ADR0043 — auditoria HTTP privada do workspace

Data: 08/10/2026 (-03). **CANDIDATE v0.6.29**, sem migração nova.

## Contexto

A API workspace schema9 já possui autenticação local, bindings SQL explícitos,
coordenador, reconciliação revisada e ponte do legado. Antes de a UI/Mapper
depender desse contrato, R06 exige auditoria HTTP própria com admissão
fail-closed e redação compatível com o isolamento de workspaces.

A auditoria v0.6.19 do operador legado não deve ser ampliada silenciosamente:
ela possui operações e metadados de assessment diferentes e é um contrato
qualificado independente.

## Decisão

Criar `P01_Workspace_Audit.py` como sink privado e opt-in, com
`audit_version=1`. O classificador usa somente operações fixas por rota e nunca
persiste rota/query original.

Registrar `operator_id` apenas após sessão confiável. Registrar
`workspace_id` somente depois do retorno bem-sucedido da operação do workspace,
de modo que uma tentativa negada ou malformada não ecoe identificador arbitrário.
Não registrar IDs de objetos, bundles, assessments, planos, revisions/generations,
payloads, tokens ou conteúdo.

O handler workspace sobrescreve apenas o envelope de auditoria. Parsing,
autorização, backend, erros, limites HTTP, bindings SQL e contratos schema9
permanecem iguais.

A falha de `begin` nega a requisição antes do handler. `finish` ocorre após a
tentativa de resposta; sua falha invalida novas admissões, mas não fabrica rollback
de uma mutação que já tenha sido commitada.

## Segurança do arquivo

Cada execução cria arquivo novo e exclusivo, com limite fixo, fsync e verificação
da identidade do descriptor/path/diretório. Reutilização, hardlink, symlink,
reparse point, mudança de tamanho/metadados ou perda de privacidade observada
trava o sink até restart controlado.

Capacidade é reservada para terminar requests já admitidos e para o fechamento
normal. Não existe reparo, rotação ou continuação no mesmo arquivo após falha.

## Consequências

Sem `--audit-file`, o listener mantém o comportamento anterior. Com auditoria
habilitada, indisponibilidade do sink pode negar trabalho legítimo por desenho.

O contrato não substitui logs de rede/OS, retenção, assinatura, SIEM, HA ou
recovery operacional. Schema9, SQL1–9, tarefas já concluídas e evidências v0.6.28
permanecem preservados.

[Contrato](WORKSPACE_AUDIT_v0.6.29.md).
