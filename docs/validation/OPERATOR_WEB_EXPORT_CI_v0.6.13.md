# Cancã — qualificação CI do download Web v0.6.13

03/10/2026 (-03). **Código CI qualificado; novo R1 manual CANDIDATE.**
Fontes fixadas em `9cb8442e4a9ff84384b6b4f42bf5c8db0a65d871`, árvore
`e4542f5e316defeaa8bd5db137b2eebb355af7a3`, no PR #113. Dados de teste sintéticos;
nenhum acesso ao LAB do Bruno ou afirmação de qualificação de produção.

## Resultados

| Gate | Evidência |
| --- | --- |
| Python 3.12 | 426 testes: 325 executados, 101 skips opcionais; PASS |
| HTTP real | Autorização/origem/query antes do banco, arquivo completo/hashes, 409/404, redaction, 429, byte/deadline bounds, revogação e liberação do slot |
| Eventos do cliente | 9 grupos: navegação/texto/sessão, download do assessment exibido, resposta inválida e logout/expiração com resposta tardia |
| Chromium | Desktop 1280 e mobile 390: login/páginas/texto inerte, download real dos quatro membros, SHA256/contagens, negação/logout/reload e sem cookies/storage/requisições externas |
| PostgreSQL 16.15 / 17.11 | 169 casos em cada matriz; novo download sob role SELECT-only, quatro páginas/terminal, igualdade canônica, quatro avaliações/duas ocorrências históricas, 14 tabelas/store invariantes |
| Recovery CI | Dump/restore/replay sintético com 14 tabelas/20 arquivos preservados em ambas as matrizes |
| Agent regression | Windows Python 3.12/3.13, Linux 3.10/3.12: quatro jobs PASS por evento, incluindo SCM/systemd/scheduler |
| Roteiros históricos | Fontes da revisão fixada v0.6.9/v0.6.12 qualificam os instaladores; arquivos/hashes/guia aprovados preservados |

Todos os oito runs (push + pull request), dezesseis jobs, passaram no head acima:

| Workflow | Pull request | Push |
| --- | --- | --- |
| Python | [37128386783](https://github.com/brunosfs-droid/canca/actions/runs/37128386783) | [37128384115](https://github.com/brunosfs-droid/canca/actions/runs/37128384115) |
| PostgreSQL 16/17 | [37128386745](https://github.com/brunosfs-droid/canca/actions/runs/37128386745) | [37128384155](https://github.com/brunosfs-droid/canca/actions/runs/37128384155) |
| Operator Web | [37128386747](https://github.com/brunosfs-droid/canca/actions/runs/37128386747) | [37128384116](https://github.com/brunosfs-droid/canca/actions/runs/37128384116) |
| Optional Agent | [37128386779](https://github.com/brunosfs-droid/canca/actions/runs/37128386779) | [37128384134](https://github.com/brunosfs-droid/canca/actions/runs/37128384134) |

Artefato `operator-web-synthetic-screens`, ID 11276280441, contém quatro PNGs e
dois ZIPs de relatório; SHA256
`6150ad7bf1d3986acab52e74a51119ddab7d2d8267c7f6b24568d87dc8863ee8`.
Hash/inventário foram conferidos e os relatórios desktop/mobile inspecionados
visualmente: botão/texto legíveis e overflow da tabela restrito à região própria.
Retenção do artefato de CI: sete dias; os testes/fontes permitem reproduzi-lo.
O Chromium local não estava disponível; a qualificação gráfica acima é do CI.

## Limites e próximo gate

Não qualifica Edge/Windows–Rocky manual, HTTPS remoto, produção, AD/MFA, HA,
acessibilidade completa, carga ou grandes relatórios. Deadline é cooperativo:
uma consulta em andamento mantém o timeout SQL existente; aborto no navegador
não cancela imediatamente SQL. Hash não é assinatura nem prova de autoria.
Arquivos salvos permanecem no computador do operador após logout.

O gate pendente é apenas o novo download via túnel e FILE PASS/STOP PASS na fixture
recuperada, usando o [roteiro fixado](../LAB_OPERATOR_WEB_EXPORT_R1_v0.6.13.md).
Não repetir Web/API/restore/lifecycle/exportação CLI nem serviços anteriores.
Sem mudanças de coleta, credenciais de alvos, mTLS, schema ou evidência bruta.

[Decisão](../ADR_0025_Operator_Web_Report_Export_v0.6.13.md) ·
[Guia](../OPERATOR_WEB_EXPORT_v0.6.13.md) ·
[Web R1 aprovado](LOCAL_OPERATOR_WEB_P01LAB_R1_v0.6.12.md).
