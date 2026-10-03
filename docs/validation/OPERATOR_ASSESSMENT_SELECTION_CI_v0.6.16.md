# Seleção de assessments v0.6.16 — registro de qualificação

Data: 03/10/2026 (-03). Status: CANDIDATE operacional.

Fonte e resultados de CI serão fixados após os checks da revisão executável.
O incremento usa apenas os grants locais da sessão para a lista; a consulta de
relatório e os downloads preservam a autorização por assessment e seus formatos.
O código v0.6.15 e seus resultados permanecem no pin
`2db86d56f3077babc00eacb0a94cb885e2966348`.

## Verificação local

- Suíte Python completa: 462 casos, 355 executados e 107 skips opt-in, PASS.
- Oito casos novos de accessor/auth/HTTP real, PASS; listagem sem SQL e revogação
  entre snapshot/envio incluídas. O listener API standalone não oferece a rota.
- Cliente Node: 15 grupos de comportamento, PASS; listas vazias/máximas/inválidas,
  fallback e respostas antigas após entrada de outra sessão incluídos.
- Compilação Python/JS e `git diff --check`, PASS.
- Onze arquivos de API/exportadores/CLI/guias/helpers/verificadores são idênticos
  ao base v0.6.15 `ed410f13192fb053cc3b787552c6e9ca25836c51`.

Os testes de instalação v0.6.11 agora usam os bytes do pin do próprio guia, como
os testes v0.6.12/v0.6.13. O guia e o pacote histórico permanecem preservados.
O manifesto executivo continua delivery v0.6.15, independente da versão da Web.

Não há validação manual solicitada hoje. Os gates adiados de download v0.6.13 e
relatórios v0.6.14/v0.6.15 permanecem distintos; a listagem v0.6.16 não os aprova.
Não repetir R1 já aceitos, instalação, restore, lifecycle ou serviços do LAB.

[Contrato](../OPERATOR_ASSESSMENT_SELECTION_v0.6.16.md) ·
[ADR](../ADR_0028_Operator_Assessment_Selection_v0.6.16.md).
