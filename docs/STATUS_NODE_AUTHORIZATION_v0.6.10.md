# Cancã — status v0.6.10

**CANDIDATE:** política opt-in de Discovery Node/assessment na API mTLS.
Permissões `bundle:ingest` e `bundle:read` são independentes. Ausência de grant
nega acesso, mantendo binding certificado/header/manifest e propriedade do
bundle. Política limitada, validada antes do startup e imutável durante a sessão;
revogação exige restart controlado. Sem migração, UI ou principal de usuário.

Qualificação inclui 12 casos novos: políticas inválidas/duplicadas/limites,
negação antes do body/importer/index, import/replay/consulta sintéticos e conexão
mTLS real com certificados sintéticos. CI e aceites de host são gates distintos.
Não aplicar automaticamente no deployment Rocky aprovado; não repetir restore,
lifecycle, soak ou coleta. Autorização de usuários/API Web continua futura.

v0.6.8 continua LAB VALIDATED no cenário sintético. O exportador funcional v0.6.9
também está LAB VALIDATED no R1 Rocky: cinco capturas posteriores demonstram
instalação corrigida, dois JSONs `exported`, verificador PASS e exportação `true`.
[Aceite e limites](validation/POSTGRESQL_P01LAB_EXPORT_R1_v0.6.9.md).
Tentativas 003724/003738/003753 são históricas; não repetir o ensaio aprovado.
Revisão de apresentação do Markdown ainda está pendente e é independente desta
política de autorização de nodes, que continua CANDIDATE.

[Guia](NODE_AUTHORIZATION_v0.6.10.md) · [ADR 0021](ADR_0021_Node_Assessment_Authorization_v0.6.10.md) ·
[Exportador Rocky](LAB_POSTGRESQL_EXPORT_R1_v0.6.9.md).
