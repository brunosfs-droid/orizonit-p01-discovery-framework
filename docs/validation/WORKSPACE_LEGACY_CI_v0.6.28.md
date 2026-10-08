# Workspace Legacy v0.6.28 — qualificação CI

08/10/2026 (-03). **CANDIDATE opt-in schema9**.
[PR #139](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/pull/139). Tarefas1–3 e a reconciliação da PR #138 preservadas.

Fonte: `4ab193c423c07003a700f0f9cc34ea38ea3808b0`; tree `d86452d08fa6090ba2d9151fce36c0e467a566fb`.
Base: `8dda792e24f1865793616a5021b7dc7f66ebbce9`. A documentação e o ajuste do
diagnóstico Chromium recebem CI no head final da PR antes da integração.

## Evidência

15 runs/41 jobs da fonte concluídos com success, incluindo CodeQL, Linux/Windows,
regressão geral, contratos PostgreSQL legados e Workspace CI. As etapas críticas
foram conferidas; skips de plataforma/opt-in são explícitos, não casos SQL omitidos
do gate workspace.

Python CI da fonte: **784 casos / 567 executados / 217 skips esperados**, PASS,
[job113249019895](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758537981/job/113249019895).
A regressão local inicial registrou783 casos/216 skips, sem falhas; ajustes posteriores
foram verificados por compilação, suite local do legado23/18 skips e guard, e pela
regressão completa remota da fonte acima. PostgreSQL real/restore não foi executado
localmente.

Workspace CI: **141 casos por PostgreSQL, sem skips**, PASS:18 foundation +
27 coordinator +30 model +13 service +19 API +10 recovery +23 legado +um guard.
Cada job executa restores independentes schema8 e schema9. Os quatro jobs
push/pull_request passaram; logs dos dois jobs da PR conferidos.

| PostgreSQL | Job da PR | Testes e restore |
| --- | --- | --- |
| 16 (160015) | [113249051201](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547324/job/113249051201) | 141 / zero skips / restore8+9 PASS |
| 17 (170011) | [113249051407](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547324/job/113249051407) | 141 / zero skips / restore8+9 PASS |

A fixture produz imports/assets/findings genuínos em schema4 antes do upgrade9.
Verifica mapping/grants antes dos bytes, reader sem SELECT legado, RLS A/B/contexto
forjado, fonte alterada, projeção histórica corrompida antes da prévia, snapshot/revisão
alterados, cursor de relatório, preview sem incremento, IDs/linhas/bytes preservados,
evidence_only, ausência de análise distinta de limpo, replay após fonte perdida e
revisão nova, cópia falha/rollback e perda real da sessão lease antes do commit.
Close durante preparo suprime migração e o teste HTTP usa autenticação/SQL reais.
Engine corrente é bloqueada no teste que preserva avaliações. Upgrade8→9 durante
coordenador vivo reverte sem publicar tabelas/migration9; SQL1–8/checksums preservados.

Restore8 compara28 tabelas; restore9 compara30, conservando planos/cópias históricas,
relatório com avaliações/IDs, recibos e stores originais. Hashes de inventário,
projeções e snapshots coincidem; corrupção de receipt é recusada, FORCE RLS/ACLs
mantidos, runtime reinicia closed/generation nova, XIDs limpos e token antigo negado.
A primeira escrita incrementa a revisão preservada. O relatório compara conteúdo
sob revisão; a geração da sessão nova não é identidade de conteúdo.

PostgreSQL CI legado:206 casos/192 executados/14 skips workspace opt-in por PG16/17,
PASS, com restore4 independente. Esse workflow não substitui o gate workspace acima.

## Runs da fonte

| Workflow | pull_request | push |
| --- | --- | --- |
| Workspace Foundation CI | [37758547324](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547324) | [37758537993](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758537993) |
| Python CI | [37758547350](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547350) | [37758537981](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758537981) |
| CodeQL | [37758547426](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547426) | — |
| Read-only SNMP CI | [37758547476](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547476) | [37758537969](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758537969) |
| Operator Accounts CI | [37758547407](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547407) | [37758538022](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758538022) |
| Operator Web CI | [37758547318](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547318) | [37758538044](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758538044) |
| PostgreSQL CI | [37758547376](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547376) | [37758537987](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758537987) |
| Optional Agent CI | [37758547432](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758547432) | [37758538061](https://github.com/brunosfs-droid/orizonit-p01-discovery-framework/actions/runs/37758538061) |

## Limites e próximos marcos

Backfill é revisado por bundle e cobre identidade/evidence_only e análises0.6.4
já persistidas; não é migração de todas as categorias, execução de findings novos
ou relatório agregado/exportação do workspace inteiro. Mapping administrativo e
fonte congelada são pré-requisitos; os bytes e IDs originais não são substituídos.
Listener atual exige9, versões7/8 anteriores permanecem pinadas.

Restores são pequenos/quiescentes, same-cluster/major com roles sintéticas já
existentes. Não qualificam recuperação cross-cluster de roles/segredos/certificados/
configuração, backup operacional concorrente, PITR/HA ou RPO/RTO. Dumps/stores
temporários foram removidos; hashes/flags nos logs não são benchmark.

Próximo gate: audit HTTP workspace. Migração/categorias/readers adicionais, adapters
legados, UI/Mapper e recovery operacional continuam pendentes. R01–R06/T13/R20
permanecem parciais; Alpha aberta. Nenhuma operação no LAB ou teste humano solicitado.
[Contrato](../WORKSPACE_LEGACY_v0.6.28.md).
