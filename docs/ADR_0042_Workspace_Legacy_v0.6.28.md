# ADR0042 — ponte revisada do legado e relatórios históricos

Data:08/10/2026 (-03). CANDIDATE opt-in schema9.

## Contexto

Registry, coordenador, modelo/reconciliação, API humana e recovery isolado já
estão integrados nas PRs #133–138. A continuidade exige importar evidência legada
sem ownership inferido, merge silencioso ou acesso amplo ao store/SQL compartilhado.
As avaliações persistidas precisam conservar sua engine/catalogue e cobertura.

## Decisão

Adicionar SQL9 com planos/cópias imutáveis e uma função privada SECURITY DEFINER
que consulta somente o bundle explicitamente mapeado à base autorizada. A função
revalida o contexto SQL, não aceita role/path/assessment arbitrário e revoga
EXECUTE público. Preservar SQL1–8 e os contratos legados pinados.

Reutilizar o modelo de identidade com prévia por revisão, revisão manual e
evidence_only. Compor seu apply dentro da mesma transação cercada que captura as
avaliações históricas e o recibo. O preparo de bytes permanece fora da transação,
como job cancelável do coordenador; a aplicação confirma novamente fonte e contexto.

Ler/copiar as avaliações existentes, sem executar a engine de findings atual.
Ausência de análise significa não analisado. Relatório por bundle possui revisão,
hash de escopo e paginação limitada; não inventa tempo de coleta nem fecha findings.
O recibo confirmado permite reconciliar resposta perdida sem depender da fonte.

## Consequências

O mapping administrativo e os grants do workspace devem preceder acesso ao legado.
LegacySources permite store original compartilhado somente para leitura; novos
imports mantêm roots disjuntos. Atores não recebem SELECT nas tabelas antigas.
Prévia pode deixar plano de identidade não utilizado numa corrida, sem publicar
inventário/histórico parcial. Fonte legada deve permanecer congelada para revisão.

API atual exige9; versões7/8 continuam pinadas nos commits qualificados. Restore
schema9 é qualificado separadamente do schema8, no mesmo cluster com roles já
existentes. Backfill completo, audit HTTP e recovery operacional seguem abertos;
os testes sintéticos não encerram R01–R06 ou a Alpha.

[Contrato e limites](WORKSPACE_LEGACY_v0.6.28.md).
