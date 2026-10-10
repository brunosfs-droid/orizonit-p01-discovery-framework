# Seleção de assessments v0.6.16 — registro de qualificação

Data: 03/10/2026 (-03). Status: CANDIDATE operacional.

Fonte executável qualificada: `0cbba0c2742b4c10d59c993e65680c208de98c48`.
Tree completo: `cfb6d04a84ef2df8a92ba28e0f998dac90168432`.
Base: `ed410f13192fb053cc3b787552c6e9ca25836c51`.
Oito runs / 16 jobs completados com sucesso nesse head, com etapas executadas.
O tree remoto foi comparado com o repositório local completo, preservando também
os arquivos binários/branding. Revisão posterior deste registro altera apenas docs.

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

## GitHub Actions da fonte qualificada

| Evento | Workflow | Run |
| --- | --- | --- |
| pull_request | Python CI | [37149241771](https://github.com/brunosfs-droid/canca/actions/runs/37149241771) |
| pull_request | PostgreSQL CI | [37149241798](https://github.com/brunosfs-droid/canca/actions/runs/37149241798) |
| pull_request | Operator Web CI | [37149241772](https://github.com/brunosfs-droid/canca/actions/runs/37149241772) |
| pull_request | Optional Agent CI | [37149241767](https://github.com/brunosfs-droid/canca/actions/runs/37149241767) |
| push | Python CI | [37149223308](https://github.com/brunosfs-droid/canca/actions/runs/37149223308) |
| push | PostgreSQL CI | [37149223290](https://github.com/brunosfs-droid/canca/actions/runs/37149223290) |
| push | Operator Web CI | [37149223288](https://github.com/brunosfs-droid/canca/actions/runs/37149223288) |
| push | Optional Agent CI | [37149223291](https://github.com/brunosfs-droid/canca/actions/runs/37149223291) |

- Python CI: 462 casos, 355 executados / 107 skips opt-in, PASS.
- PostgreSQL **16.15 / 17.11**: **186 casos cada, sem skips**, PASS. O caso novo
  `test_directory_is_sql_free_and_reader_reports_preserve_fourteen_tables_and_store`
  aparece como `ok` nos dois logs. Grants incluem um ID inexistente; listar não
  abre conexão, consultar usa reader SELECT-only, OTHER é negado antes de SQL e
  logout revoga a lista. As 14 tabelas e os arquivos da fixture permanecem iguais.
- Backup/restore lógico: PASS nas duas versões, 14 tabelas / 20 arquivos e replay.
  A linha fixa `backup_restore_failed` no output da suíte é o teste negativo do
  guardrail, não uma falha do job nem do restore subsequente.
- Node: **15 grupos**, PASS. Chromium real a **1280 / 390 px**, PASS: opções de
  duas contas separadas, conta sem grants, refresh, ID permitido inexistente,
  seleção sem query automática, negação do ID manual OTHER e limpeza após logout.
  Paginação e ambos os downloads continuam exercitados; sem cookies/storage,
  requests externos ou HTML injetado pelas strings sintéticas do relatório.
- Agent: quatro combinações Linux/Windows e Python, PASS. Etapas nativas
  systemd/SCM, interrupção, tamper e intervalo real do scheduler executadas nas
  respectivas plataformas. Skips da outra plataforma são condicionais previstos.

## Artefatos do navegador e verificação independente

Artifact `11282184276`, `operator-web-synthetic-screens`, do run PR Web acima;
520937 bytes. SHA256 do ZIP externo:
`f9b3cea675a37b6a8325a4bf97e24aab875c9ffc3674c36aeef19a79d9420b11`.
Retenção do workflow: sete dias. O pin, runs e hashes deste registro ficam em Git.

Inventário externo de dez membros fixos, sem duplicatas, validado antes de ler:
login/assessments/report PNG a 1280 e 390 px, mais os quatro ZIP de relatórios.
Os dois PNG do seletor foram inspecionados: rótulos, lista, atualização e formulário
legíveis, sem sobreposição; atualização ocupa a largura disponível no mobile.

Os quatro downloads foram conferidos novamente fora do browser pelos
verificadores stdlib qualificados. Cada relatório contém quatro membros e quatro
avaliações / dois findings históricos; o executivo contém dois grupos. Query
terminal vazia confirmada e nenhuma evidência bruta/extraída no executivo.

| Arquivos | SHA256 | Resultado |
| --- | --- | --- |
| report-1280.zip / report-390.zip | `8b828ed3efb3b7714efe4ce96b8158ec753dfc400a4d71c9a848b7d391418bb9` | FILE PASS v0.6.13 |
| executive-1280.zip / executive-390.zip | `c39b02f37f3816a731179fea1b09a800a27ad649a4d97193bdc3944fcd795cf3` | EXECUTIVE FILE PASS v0.6.15 |

Esses ZIP da fixture são byte a byte iguais aos artefatos qualificados em
v0.6.15. Isso demonstra preservação deste formato/dataset; não garante hashes
iguais em fontes diferentes ou snapshots de PostgreSQL com outros timestamps.
Hashes verificam integridade, não assinatura/autenticidade do autor.

## Limites operacionais preservados

Não há validação manual solicitada hoje. Os gates adiados de download v0.6.13 e
relatórios v0.6.14/v0.6.15 permanecem distintos; a listagem v0.6.16 não os aprova.
Não repetir R1 já aceitos, instalação, restore, lifecycle ou serviços do LAB.
Uma lista de grants não é inventário nem confirmação de existência. Não há
qualificação de AD/SSO, tenancy, quotas comerciais, TLS remoto de produção ou
novas plataformas de coleta. Nenhum collector passa a exigir login Cancã.

[Contrato](../OPERATOR_ASSESSMENT_SELECTION_v0.6.16.md) ·
[ADR](../ADR_0028_Operator_Assessment_Selection_v0.6.16.md).
