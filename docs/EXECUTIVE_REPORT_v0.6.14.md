# Cancã — relatório executivo v0.6.14

**CANDIDATE para LAB.** Desenvolvimento independente do download Web v0.6.13,
cuja validação manual foi adiada pelo mantenedor em 03/10/2026 (-03).
Código qualificado em oito runs/16 jobs de CI; [resultados](validation/EXECUTIVE_REPORT_CI_v0.6.14.md).
O incremento CLI v0.6.14 preservou os onze arquivos do pacote Web fixado em
`9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871`. A integração posterior
[Web v0.6.15](OPERATOR_WEB_EXECUTIVE_v0.6.15.md) usa fontes novas, mantendo o
pacote histórico nesse pin. Não repetir os R1 já aprovados.

O novo CLI resume o relatório técnico completo do assessment: cobertura,
pendências, decisões de identidade, severidades históricas e recomendações
consolidadas com referências de todas as ocorrências. Usa somente os metadados
persistidos e os catálogos históricos; não reexecuta regras nem acessa o store.

## Operação local

Python 3.12+, PostgreSQL 16/17 e o driver opcional existente. Schema mínimo 4;
mesma conta com USAGE/SELECT do [relatório técnico](ASSESSMENT_REPORT_v0.6.5.md),
sem INSERT/UPDATE/DELETE/CREATE. A conta do sistema operacional e a conta do
banco controlam este CLI local. Os grants de sessão Web pertencem ao listener
Web; o CLI não cria sessão de operador nem endpoint HTTP.

Use as configurações explícitas libpq já documentadas em
[persistence](../persistence/README.md), com credenciais externas ao comando
(por exemplo, PGPASSFILE). Não há argumento de senha ou DSN.

Em um ambiente dedicado com metadados sintéticos, escolha uma raiz de saída
privada fora do store, existente e sem symlinks/aliases. O exemplo ilustra a
operação futura; não solicita instalação ou teste no LAB hoje.

```bash
mkdir -p /var/lib/canca/executive-exports
chmod 700 /var/lib/canca/executive-exports
python persistence/P01_Executive_Report.py \
  --assessment-id LAB-001 \
  --output-root /var/lib/canca/executive-exports --page-size 100
```

Resultado `exported`, exit 0, com `export_dir`, SHA256 do manifesto, escopo,
contagens de avaliações, ocorrências históricas e grupos. Cada execução publica
um novo diretório `P01-EXECUTIVE-*`, sem sobrescrever saídas anteriores.
`--page-size 1..100` altera somente a paginação, nunca a abrangência do resumo.
O CLI também aceita `--expected-scope-sha256` para exigir o escopo de um relatório
técnico anterior; use os 64 caracteres reais, não um placeholder. Uma mudança
normal de escopo bloqueia a operação sem retry e sem publicar arquivos.

| Arquivo | Conteúdo |
| --- | --- |
| executive.json | Resumo, contagens, grupos e todas as referências de ocorrências |
| executive.md | Apresentação executiva com cobertura, identidade, severidades, recomendações e proveniência por grupo |
| manifest.json | Versão, assessment, escopo, tamanho/SHA256 de JSON e Markdown |
| manifest.json.sha256 | SHA256 dos bytes do manifesto |

No POSIX, diretório 0700 e arquivos 0600. Os quatro arquivos são preparados e
limitados antes de criar staging, escritos de forma exclusiva, sincronizados e
publicados por rename de diretório na mesma raiz/filesystem. Máximo **32 MiB para
o conjunto completo**, sem truncar dados. Uma falha tratada remove somente seu
staging; uma interrupção abrupta pode deixar `.P01-EXECUTIVE-*`, que não representa
uma exportação concluída. Windows ACLs e durabilidade do rename após perda de
energia não foram qualificados. O operador escolhe uma raiz externa ao store;
o CLI não conhece sua localização.

## Leitura dos indicadores

Os totais descrevem os imports persistidos do assessment, sem percentuais de
cobertura de uma rede cujo tamanho não foi estabelecido. `no_imports`, projeções
ausentes e análises pendentes continuam visíveis. Os cinco resultados permanecem
separados por total e por regra: finding, no_finding, insufficient_evidence,
not_applicable e not_supported. Nenhum resultado isolado comprova ambiente seguro.

Findings são **ocorrências históricas**, não vulnerabilidades únicas ou inventário
de risco atual. Uma coleta posterior sem finding mantém as ocorrências anteriores;
`completed` continua sendo lifecycle administrativo. A classificação de severidade
vem do catálogo salvo e não é recalculada.

Uma recomendação só nasce de um finding registrado. Seu grupo combina regra,
versão da regra, policy, SHA256 do catálogo e SHA256 do engine. Catálogos ou engines
diferentes permanecem separados mesmo com texto igual. Ordenação de apresentação:
Critical, High, Medium, Low, Informational; valores históricos diferentes são
preservados após essa sequência. Isso não cria SLA, score ou ação de remediação.

Cada grupo informa ocorrências, assets centrais distintos vinculados, ocorrências
sem asset central e ocorrências com revisão de identidade. O mesmo asset pode
aparecer em vários grupos; não some os totais de assets para inferir um total único
afetado. As decisões/reasons de identidade do assessment também são mantidas.

O JSON contém referências completas: finding/status salvo, análise/ordinal,
bundle, SHA256 da fonte e asset/decisão. Use um relatório técnico **do mesmo escopo**
para consultar detalhes. O resumo exclui caminhos de fontes, evidência extraída,
referências internas de evidência e payloads brutos; ainda contém metadados
confidenciais e exige controle de acesso local. Não há leitura do store nem
validação dos bytes de evidência na geração. Valores livres persistidos são
escapados na apresentação Markdown para manter HTML/links/imagens inertes.

## Consistência e qualificação

Reutiliza a coleta completa v0.6.9 e o relatório canônico v0.6.5: transações
REPEATABLE READ READ ONLY por página, todas as continuações e uma consulta terminal
vazia sob a mesma cerca de escopo. A síntese verifica contagens, ordem/duplicatas,
mapeamento de análise/catálogo e igualdade da regra histórica antes de publicar.
Essa cerca detecta mudanças normais, sem ser snapshot durável ou defesa contra
alteração SQL direta por DBA. Timestamps da primeira/última consulta são registrados
e podem variar entre execuções; um hash de arquivo não autentica autoria.

Limites herdados: 100 imports, 10.000 observações/avaliações e as duas regras WinRM
atuais. Não há nova migração, dependência, autenticação, coleta ou mudança na Web.
Falhas retornam JSON com código fixo e exit 2, sem exceção/DSN/caminho privado.

Testes sintéticos e PostgreSQL 16/17 de CI cobrem semântica histórica, agrupamento,
metadados preservados, cobertura incompleta, escaping, hashes/permissões, papel
SELECT-only, conflitos de escopo e invariância das 14 tabelas/store.
O harness opt-in apaga o schema do serviço descartável `canca_ci`; não executá-lo
no LAB ou em banco de cliente. [Registro de qualificação](validation/EXECUTIVE_REPORT_CI_v0.6.14.md).

Qualificação operacional manual fica para uma etapa futura. Integração Web/API,
PDF e renderização gráfica não estão entregues por este CLI. O gate de download
v0.6.13 permanece independente e pendente.

[ADR 0026](ADR_0026_Executive_Report_v0.6.14.md) · [MVP](MVP.md).
