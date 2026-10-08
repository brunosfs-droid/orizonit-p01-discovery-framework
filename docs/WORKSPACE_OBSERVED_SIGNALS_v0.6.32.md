# Cancã v0.6.32 — Leitor inicial de sinais observados

## Escopo implementado

O módulo `server/P01_Workspace_Observed_Signals.py` usa exclusivamente `model.object_state` (escopo autenticado, workspace e revision fence) por meio de `WorkspaceService.observed_signals` com grant `workspace:read`.

Este incremento distingue **observações persistidas** de atributos **declarados manualmente**. Cada observação inclui `collection_id`, `ordinal`, revisão e horário de recebimento da importação; `source_reference_recorded` indica a presença de referências sem expor caminhos nem o conteúdo de `source_refs`. Sinais são projetados apenas de observações registradas, nunca de declarações.

Limites: máximo de 100 observações por objeto (limite do próprio modelo), máximo de 1.000 sinais processados e no máximo 50 observações por página. O cursor `after` representa a posição na lista da revisão corrente; a continuação exige `expected_revision`. O contrato expõe `complete` e `next_after`, sem extrapolar completude do ambiente. Horários são de recebimento, não prova do instante da coleta.

## Testes

Suite `tests/test_workspace_observed_signals.py` cobre paginação, redaction de referências, exclusão de declarações, autorização delegada ao model, revision fence e falha fechada diante de dados incorretos. Workspace Foundation CI executa a suite na matriz PostgreSQL 16/17.

## Gates não atendidos neste incremento

- Endpoint HTTP autenticado e contratos de UI ainda não implementados.
- Rastreabilidade de evidências até conteúdo imutável, verificação de integridade e sinais de outros conectores continuam pendentes.
- Amplitude de dispositivos, coleta real, mapper e reconciliação semântica permanecem fases futuras.
- EVE-NG, restore operacional multicompontente e Product Alpha exigem validação própria.

**Estado:** candidata em branch; não declarar v0.6.32 integrada ou qualificada antes de CI e revisão do PR.
