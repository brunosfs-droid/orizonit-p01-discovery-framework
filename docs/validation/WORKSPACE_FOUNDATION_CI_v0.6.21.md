# Workspace Foundation v0.6.21 — qualificação CI

Data: 07/10/2026. Status: **CANDIDATE opt-in**, fonte qualificada em CI;
operação em LAB e migração completa de inventário permanecem pendentes.

Fonte executável: `1ede18c4eba768cbe17fe77e46a7dfa98ed11b85`.
Tree: `6564b7be345fda895bcd3c9da4b399e187dcbe7c`.
Base: `2f72ea3a1effba7334c7228c5c86b40410d090b7`.
[PR #133](https://github.com/brunosfs-droid/canca/pull/133).
O commit seguinte deste registro altera apenas documentação.

## Verificação local

- Suíte Python completa: **661 casos / 507 executados / 154 skips opt-in**, PASS.
- Testes de exportação HTTP: nove casos, PASS.
- Compilação, diff check e links relativos dos documentos modificados, PASS.
- PostgreSQL local não foi usado como prova: integração real foi executada no CI.
- A saída `backup_restore_failed` no caso negativo de restore é esperada;
  a suíte concluiu com exit 0.

## PostgreSQL dedicado: isolamento real

O workflow Workspace Foundation CI cria banco descartável próprio e executa
`test_postgres_workspace.py` com `CANCA_TEST_WORKSPACE_POSTGRES=1`.
Esse modo apaga o schema canca somente no banco de teste dedicado.

| PostgreSQL | Job da PR | Casos | Skips | Resultado |
| --- | --- | --- | --- | --- |
| 16 | [112720752873](https://github.com/brunosfs-droid/canca/actions/runs/37599692743/job/112720752873) | 18 | 0 | PASS |
| 17 | [112720752576](https://github.com/brunosfs-droid/canca/actions/runs/37599692743/job/112720752576) | 18 | 0 | PASS |

Quatro contratos puros e quatorze testes de integração por versão. Logs e etapas
dos dois jobs foram conferidos; não há skip substituindo o teste de banco real.
As rejeições SQL de casos negativos são esperadas e verificadas pelos testes.

Cobertura: RLS forçada nas cinco tabelas novas; contexto forjado sem grant;
IDs iguais em A/B; grants read/write e revogação; tentativa SQL direta de
escrita/grant indevido; parent de outra base; self/ciclo em INSERT multirow;
rollback/contexto restaurado; paginação e conexão reutilizada; replay/conflito;
mapping legado imutável; preservação dos dados legados; migração parcial
revertida; registro concorrente; rejeição de transação iniciada pelo caller.

## Regressão no GitHub Actions

**15 runs concluídos com success** na fonte acima: oito de pull_request e sete
de push. Cada célula abaixo aponta para o run correspondente.

| Workflow | pull_request | push |
| --- | --- | --- |
| Workspace Foundation CI | [37599692743](https://github.com/brunosfs-droid/canca/actions/runs/37599692743) | [37599687697](https://github.com/brunosfs-droid/canca/actions/runs/37599687697) |
| Python CI | [37599692663](https://github.com/brunosfs-droid/canca/actions/runs/37599692663) | [37599687723](https://github.com/brunosfs-droid/canca/actions/runs/37599687723) |
| PostgreSQL CI | [37599692766](https://github.com/brunosfs-droid/canca/actions/runs/37599692766) | [37599687678](https://github.com/brunosfs-droid/canca/actions/runs/37599687678) |
| Operator Accounts CI | [37599692702](https://github.com/brunosfs-droid/canca/actions/runs/37599692702) | [37599687546](https://github.com/brunosfs-droid/canca/actions/runs/37599687546) |
| Operator Web CI | [37599692727](https://github.com/brunosfs-droid/canca/actions/runs/37599692727) | [37599687591](https://github.com/brunosfs-droid/canca/actions/runs/37599687591) |
| Optional Agent CI | [37599692780](https://github.com/brunosfs-droid/canca/actions/runs/37599692780) | [37599687575](https://github.com/brunosfs-droid/canca/actions/runs/37599687575) |
| Read-only SNMP CI | [37599692787](https://github.com/brunosfs-droid/canca/actions/runs/37599692787) | [37599687675](https://github.com/brunosfs-droid/canca/actions/runs/37599687675) |
| CodeQL | [37599692785](https://github.com/brunosfs-droid/canca/actions/runs/37599692785) | — |

Uma corrida preexistente no teste HTTP de exportação da base principal foi
corrigida: o teste aguarda a saída do contexto de entrega do handler antes
de exigir uma nova vaga. Não altera o produtor nem as regras de concorrência.

## Limites e próxima entrega

O isolamento qualificado cobre o registry, sites, ambientes e mappings novos,
com roles PostgreSQL sem SUPERUSER/BYPASSRLS e sem privileges nas tabelas legadas.
Não constitui isolamento completo do inventário legado, nem autenticação humana
por workspace. Roles de manutenção são identidades confiáveis fora dessa fronteira.

Schema 5 é opt-in em base isolada; readers/Web legados rejeitam esse schema.
Nenhuma alteração foi aplicada ao LAB operacional. Restore de schema 5,
EVE-NG/equipamentos reais, UI/Mapper e desempenho operacional não foram qualificados.

R01 permanece parcial: a migração completa e os adapters de inventário/API
virão nos incrementos posteriores. Próximo: **v0.6.22**, coordenação de carga
única com lease/generation e encerramento seguro; depois observações/identidade,
relações e reconciliação. [Guia](../WORKSPACE_FOUNDATION_v0.6.21.md).
