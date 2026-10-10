# Cancã — matriz de lacunas R01–R06 e qualificação E0

Data de referência: 08/10/2026 (-03). Base observada: `main` `00616325a0a90b9d3d1565b1617b34ed2fc88050`, integração v0.6.36 / PR #147. Os oito workflows do push desse SHA terminaram **success** (Python CI, PostgreSQL CI, Workspace Foundation CI, CodeQL, Read-only SNMP CI, Optional Agent CI, Operator Accounts CI, Operator Web CI). Isso **não** é homologação EVE-NG ou fechamento Alpha.

Este registro é um inventário de evidência e gates, não uma promoção de candidate para release. Referências normativas: `docs/BACKLOG_1.0.md`, `docs/TEST_PLAN_1.0.md`, `docs/IMPLEMENTATION_PLAN_1.0.md` e issue #63. Aceites de LAB antigos conservam seu pin e escopo; não repetir sem mudança de contrato.

## Mapeamento rastreável

| Gate | Cobertura integrada a preservar | Lacunas e contraprovas ainda exigidas | Critério de saída |
|---|---|---|---|
| R01 / T01–T02 | schema5 registry/workspaces/sites/environments, grants/RLS, mapping explícito; `test_postgres_workspace.py`, `test_workspace_model.py`, `test_workspace_api.py` | ownership de todas as fontes/store/readers, import/backfill integral, acessos indiretos B via cursors/download/cache/secret; LAB E0 bases A/B com IDs/IPs coincidentes | relatório negativo A→B por SQL/API/store + mapeamento preservado sem grant ampliado |
| R02 / T03 e T14 parcial | lease, generation, drain, cancela/cerca commits e jobs do serviço; `test_workspace_coordinator.py`, `test_workspace_service.py` | adapters de collectors/scanners/jobs legados, encerramento durante I/O real e múltiplas sessões/processos; benchmark p50/p95/RAM | zero replay de AUTH/FULL/POST, zero mistura A/B em execução/fechamento, provas de carga |
| R03 / T04–T05 | CollectionRun/Observation/identidade, backfill identity revisado e leitores de sinais/proveniência v0.6.32–36; `test_workspace_model.py`, `test_workspace_legacy.py` | categorias observadas além de identity, migração completa/idade/cobertura e imports legacy reais adicionais | bytes/IDs/hashes intactos, histórico/replay idempotente sem merges silenciosos |
| R04 / T02 e T06 backend | relações manuais, grafo limitado, ownership/escopo em `test_workspace_model.py` | interface/rede/VLAN/componente/serviço observados, ciclos/namespace, intersite e ingestão de adapters; UI Mapper pertence à v0.7 | invariantes de FK/ownership/ciclos, relação declarada distinta da observada |
| R05 / T05 e T07 | preview/apply com revision fence, recibos/rollback e legado revisado; `test_workspace_model.py`, `test_workspace_legacy.py`, `test_workspace_api.py` | export/import seletivo completo por categorias, dry-run com drift real, source/target collision, crash e reconciliação de todas as categorias | apply atômico, replay estável, nenhum overwrite/deletion implícitos |
| R06 / T01/T04/T13 (fundação) | API autenticada, auditoria HTTP fail-closed, schema8/9 e recovery mesmo cluster; `test_workspace_audit.py`, `test_workspace_recovery.py`, `test_workspace_backup_guard.py` | cross-cluster roles/grants/TLS/config/store/DB; restore de evidências, rotação da identidade de sessão, operacional E0; fechar R01–R05 | relatório de recuperação isolada + isolamento pós-restore + matriz R01–R06 PASS assinada pelo mantenedor |

`T06` (passivos/visual Mapper) e `T14` (escala) têm itens além da Alpha, e devem ser delimitados nos aceites sem declarar UI v0.7 pronta. `R20`/GA **não** fecha com a qualificação isolada R06.

## Consolidação por ambiente

- **CI já aprovado no SHA base:** Oito workflows acima; v0.6.27 PG16/17 118 testes workspace sem skips e restore sintético; v0.6.28 PG16/17 141 testes e schema8/9. Contagens são históricas, por SHA, não atribuídas automaticamente a este incremento.
- **Novo desenvolvimento nesta branch:** `docs/validation/ALPHA_E0_RECOVERY_PREFLIGHT.py` + `tests/test_alpha_e0_recovery_preflight.py`. Captura/compara hashes de dump, snapshot privado de roles, store e configuração; falha fechado, sem publicar caminhos/segredos; **somente artefatos offline**. Qualificação deve ser registrada no HEAD/CI desta branch.
- **E0 LAB:** Inventário e preflight, A/B com mesmos IDs/IPs, import/migração/fonte legada reais e testes de autorização/replay, sem executar os harnesses destrutivos de CI no LAB.
- **Recovery operacional:** quiesce, captura transacional/coerente do conjunto, transferência privada, verificação E0 de artefatos, restore em cluster isolado, roles/grants/RLS/TLS, verificação lógica e reabertura com generation nova, RPO/RTO observados.
- **E1–E7:** vendors/Network L2/virtualização/Graph/UX conforme `TEST_PLAN_1.0.md`, independentes do aceite de E0; não alegar suporte real com fixture sintética.

## Evidência obrigatória por teste

Usar campos: `case_id`, commit SHA, workflow/run/job ou hostname LAB, DB major e configuração, data/hora, pré-condição e permissão, comando/roteiro, resultado esperado, observado, status PASS/FAIL/SKIP, limite explícito, artefatos SHA256 e responsável. Logs/snapshots reais privados em private evidence archive restrito; Git somente relatório sanitizado e fixtures artificiais.

**Estado:** R01–R06 PARCIAIS; E0 operacional NÃO EXECUTADO neste incremento; cross-cluster NÃO VALIDADO. Nenhum resultado desta branch deve ser interpretado como EVE-NG PASS ou Product Alpha fechada.

Próximo passo: executar `docs/LAB_ALPHA_E0_AND_RECOVERY_R1.md` sobre base descartável e anexar relatório de evidências. Descartar prontamente qualquer fixture cujo isolamento tenha falhado; não reexecutar restore CI contra banco operacional.
