# P01 — Nota de Validação AD Stale v0.3

## Conclusão

A Rodada 2 não produziu `AD-USER-001` e `AD-COMP-001` porque a simulação tentou alterar atributos de logon controlados pelo Active Directory. `lastLogonTimestamp` é definido pelo sistema e não deve ser tratado como campo de laboratório livremente editável.

O collector v0.3 já possui duas bases de inatividade:

1. `LastLogonDate` anterior ao cutoff;
2. objeto habilitado sem `LastLogonDate`, usando `whenCreated` quando a conta nunca realizou logon.

## Estratégia correta de validação

Para LAB não alterar `lastLogonTimestamp`/`lastLogon`.

Validar o caminho funcional com uma das abordagens abaixo:

- executar o collector com threshold reduzido (`-InactiveThresholdDays 0` ou pequeno) em objetos de teste recém-criados que nunca logaram;
- criar teste unitário/sintético da função de classificação de inatividade com datas controladas;
- manter o threshold de produção em 90 dias.

O teste de 90 dias em produção utiliza `lastLogonTimestamp`/`LastLogonDate` como sinal aproximado replicado e não como auditoria exata de autenticação.

## Status

A ausência do finding na Rodada 2 não é evidência de falha do Analyzer. É uma limitação da técnica de simulação utilizada. A regra permanece no produto e deve receber teste funcional com threshold reduzido e teste sintético antes da promoção final da baseline.
