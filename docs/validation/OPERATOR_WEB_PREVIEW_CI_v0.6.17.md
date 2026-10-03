# Resumo executivo Web v0.6.17 — registro de qualificação

Data: 03/10/2026 (-03). Status: CANDIDATE operacional.

Fonte executável qualificada: `d2947213df84cdb9896ee193c421970dec39a08f`.
Tree completo: `0ac1d8f35716fb16a581604592f3a6b926e568a5`.
Base v0.6.16: `ca8fd27745853edc17d875a3c94541920e5124a2`.
Oito runs / 16 jobs completados com sucesso nesse head. Sessenta etapas críticas
foram conferidas como executadas, com conclusão success e timestamps preenchidos.
O tree remoto é igual ao tree local completo, incluindo binários/branding.
Revisão posterior deste registro altera apenas docs; nenhum código muda.

## Verificação local

- Python: **472 casos**, **364 executados / 108 skips opt-in**, PASS.
- Nove novos casos puros/HTTP, PASS: histórico completo, projeção por campos
  explícitos, 12 grupos em duas páginas, negação antes de SQL, slot entre três
  entregas, limite/deadline, liberação após erro e revogação durante as fases.
- Node: **20 grupos de comportamento**, PASS. SHA/length/MIME/escopo inválidos,
  paginação, busy guard, hide, respostas antigas após logout/nova entrada,
  expiração e históricos vazios incluídos.
- Compilação Python/JS, links relativos novos/atualizados e diff check, PASS.
- Nove arquivos de API/auth, módulos canônicos/CLI executivo, guia/helper de
  download v0.6.13 e verificadores stdlib permanecem idênticos ao base v0.6.16.
  O resource window do delivery foi extraído sem mudar formatos/conteúdo ZIP.
- A fixture LAB-001 manteve ambos os ZIP byte a byte iguais à v0.6.16 usando o
  mesmo page size de exportação 100. As novas fixtures incluem zero imports e
  12 grupos derivados de seis engines históricos distintos.

## GitHub Actions da fonte qualificada

| Evento | Workflow | Run |
| --- | --- | --- |
| pull_request | Python CI | [37154982871](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154982871) |
| pull_request | PostgreSQL CI | [37154982831](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154982831) |
| pull_request | Operator Web CI | [37154982819](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154982819) |
| pull_request | Optional Agent CI | [37154982848](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154982848) |
| push | Python CI | [37154980803](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154980803) |
| push | PostgreSQL CI | [37154980786](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154980786) |
| push | Operator Web CI | [37154980797](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154980797) |
| push | Optional Agent CI | [37154980788](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37154980788) |

- Python CI: 472 casos, 364 executados / 108 skips opt-in, PASS.
- PostgreSQL **16.15 / 17.11**: **187 casos por versão, sem skips**, PASS.
  `test_reader_preview_matches_complete_synthesis_without_mutating_fourteen_tables_or_store`
  aparece como `ok` nos dois logs. Preview HTTP via role SELECT-only concorda
  com a projeção da síntese completa, inclusive duas avaliações posteriores sem
  finding. Headers/hash, terminal vazia, escopo obsoleto, offset inexistente,
  OTHER antes de SQL e revogação foram verificados; escritas negadas.
  As 14 tabelas e todos os arquivos do store mantêm seus snapshots/hashes.
- Backup/restore lógico: PASS nos dois PostgreSQL, 14 tabelas / 20 arquivos,
  revalidação e replay preservados. `backup_restore_failed` no output da suíte
  é o teste negativo de guardrail; não indica falha do job/restore subsequente.
- Node 20 grupos e Chromium real **1280 / 390 px**, PASS. Resumo completo com
  tabela técnica de uma linha, proveniência, strings HTML tratadas como texto,
  verificação do hash, hide/limpeza, ausência de imports, 12 grupos em páginas
  10+2 e paginação técnica independente. Grants de outras contas, logout/reload
  e ambos os downloads permanecem exercitados. Sem HTML injetado, cookies,
  storage persistente, erros de página ou pedidos externos.
- Agent: quatro combinações Linux/Windows e Python, PASS. Etapas nativas
  systemd/SCM, interrupção, tamper e espera real do scheduler executadas nas
  respectivas plataformas. Skips de outra plataforma permanecem previstos.

## Artefatos e conferência independente

Artifact **11285258897**, `operator-web-synthetic-screens`, do run PR Web acima;
**1132523 bytes**, SHA256 externo
`25fa120e63313b5bbc543eec08494b5ae7d8ab95ca1d8581a8e2f1a3b563774e`.
Retenção de sete dias; fonte, runs e hashes ficam registrados em Git.

Inventário de **14 membros fixos**, sem duplicatas, validado antes de ler:
login/assessments/report/preview PNG, preview JSON e ambos os ZIP em cada largura.
Todos os membros têm até 2 MiB; nenhum nome fora do inventário é extraído.
Os PNG do resumo foram inspecionados: 1280×3050 e 390×4627. Títulos, texto,
recomendações, hashes quebrados em linhas e botões aparecem sem sobreposição;
o mobile mantém os controles dentro da largura disponível.

Os JSON recebidos nos dois browsers possuem **3685 bytes**, quatro avaliações,
dois findings históricos e dois grupos. Contagens, severidades, identidade,
proveniência/ordem dos grupos e consistência foram comparadas à síntese canônica
completa, fora do browser. Campos de ocorrências/bundle/fonte/evidência estão
ausentes; flags de risco atual e referências de ocorrências são false.

| Arquivos | SHA256 | Resultado |
| --- | --- | --- |
| preview-1280.json / preview-390.json | `316b4b43ae7fc0cbfc5d291b6d8fd8ac2d9f988dee27dd68335a281eb5677535` | Igualdade com a síntese completa e whitelist PASS |
| report-1280.zip / report-390.zip | `8b828ed3efb3b7714efe4ce96b8158ec753dfc400a4d71c9a848b7d391418bb9` | FILE PASS v0.6.13 |
| executive-1280.zip / executive-390.zip | `c39b02f37f3816a731179fea1b09a800a27ad649a4d97193bdc3944fcd795cf3` | EXECUTIVE FILE PASS v0.6.15 |

Os quatro ZIP foram novamente conferidos pelos verificadores stdlib qualificados:
quatro membros internos, quatro avaliações, dois findings e, no executivo, dois
grupos com terminal vazia verificada. São byte a byte iguais aos downloads da
fixture v0.6.16. Isso comprova esse dataset/formato; timestamps/dados de outras
fontes podem alterar hashes. Hashes verificam integridade, não autoria.

## Limites e gates preservados

Nenhuma ação no LAB hoje. A qualificação de CI não aprova os gates operacionais
adiados de download v0.6.13, síntese v0.6.14, Web v0.6.15/v0.6.16 ou este painel.
Não repetir R1 aceitos, instalações, restore, lifecycle ou serviços.

Sem migração, escrita no banco/store, nova dependência, collector login, alvo,
AD/SSO, inventário/mapper ou quota comercial. Formatos e guias históricos retêm
seus pins. A API standalone e o diretório v0.6.16 preservam seus contratos.
Um slot por listener, 1 MiB de preview e limites completos herdados continuam
explícitos. Cada página recolhe todo o escopo; deadline é cooperativo, sem
cancelamento imediato de SQL pelo browser. Roles/TLS de produção, tenancy e
plataformas live permanecem gates próprios. Histórico não calcula risco atual.

[Contrato](../OPERATOR_WEB_PREVIEW_v0.6.17.md) ·
[ADR 0029](../ADR_0029_Operator_Executive_Preview_v0.6.17.md).
