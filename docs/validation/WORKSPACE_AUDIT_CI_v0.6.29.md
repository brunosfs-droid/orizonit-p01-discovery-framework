# Cancã — qualificação Workspace HTTP Audit v0.6.29

Data: 08/10/2026 (-03). Branch de qualificação:
`feature/workspace-http-audit-v0.6.29`.

## Escopo comprovado

- `P01_Workspace_Audit.py`: arquivo JSONL novo/exclusivo, privado, limitado,
  fsync, identidade de arquivo/diretório verificada e falha latched.
- Classificação fixa de login/logout/health, registry, open/close, objeto/grafo,
  alterações manuais, import preview/apply, legacy preview/apply e relatório.
- Redação: token/senha/body/query, bundle/assessment/object/plan/scope e erros
  brutos não são persistidos.
- `operator_id` vem de autenticação válida; `workspace_id` só é publicado
  depois de operação workspace bem-sucedida.
- Falha/adulteração/capacidade de audit bloqueia nova admissão antes de
  autenticação/SQL/serviço.
- Schema9, SQL1–9, ponte legacy, relatórios e restores anteriores permanecem
  inalterados.

## Evidência CI

Head de código qualificado: `a581ba39364d391a95a6f96cf188d78a6966ed1a`.

- Python CI run 37771272816: PASS.
  - regressão geral: **793 testes PASS**, **217 skips esperados**;
  - compilação Python e artefatos JSON: PASS.
- Operator Web CI run 37771272900: PASS.
- Workspace Foundation CI run 37771272873: PASS.
  - PostgreSQL 17 job 113291172487: PASS;
  - PostgreSQL 16 job 113291172816: PASS;
  - audit dedicado: **9 testes PASS sem skips em cada versão**;
  - isolamento, coordenador, model, service, API humana, recovery e legacy: PASS;
  - restore schema8: PASS em PG16/17;
  - restore schema9 com relatório/recibo legacy: PASS em PG16/17.

Os workflows restantes do repositório não definem o contrato do audit, mas a PR
deve manter a regressão global verde antes de integração.

## O que não é provado

A qualificação não transforma o JSONL em log imutável/assinado, SIEM ou retenção.
Não comprova ACL Windows de produção, TLS/proxy/OS logging, recovery cross-cluster,
upgrade operacional, LAB real, migração completa, readers/categorias adicionais,
UI/Mapper ou fechamento R01–R06/Alpha.

[Contrato](../WORKSPACE_AUDIT_v0.6.29.md) ·
[ADR0043](../ADR_0043_Workspace_HTTP_Audit_v0.6.29.md).
