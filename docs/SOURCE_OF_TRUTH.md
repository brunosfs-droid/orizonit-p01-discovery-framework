# P01 — Política de Source of Truth: GitHub x Google Drive

Versão: 1.0

## Princípio

O P01 passa a ter duas fontes de verdade complementares, sem manter cópias editáveis concorrentes.

### GitHub — fonte de verdade de engenharia

Deve conter:

- código-fonte atual;
- testes automatizados;
- schemas;
- regras do Analyzer;
- exemplos sanitizados;
- documentação necessária para instalar, executar, desenvolver e revisar o software;
- ADRs/decisões arquiteturais;
- roadmap técnico e issues;
- workflows de CI;
- CHANGELOG, SECURITY, CONTRIBUTING e release notes.

As versões de código são preservadas por commits, tags e releases. Não é necessário manter cópias `v0.1`, `v0.2`, `v0.3` do mesmo fonte dentro da árvore principal, exceto quando o formato/versionamento do artefato exigir coexistência (por exemplo schemas compatíveis).

### Google Drive — fonte de verdade de produto, governança e evidência

Deve conter:

- CI/governança do produto;
- oferta comercial, escopo e documentos institucionais;
- procedimentos operacionais e implantação aprovados;
- LAB, aceite, evidências e resultados brutos de testes;
- JSONs/SHA256 reais de validação;
- relatórios técnicos e executivos gerados;
- entregáveis de cliente;
- documentos assinados/aprovados;
- pacotes de release quando for necessário manter snapshot formal fora do GitHub;
- histórico documental e artefatos não adequados ao repositório de código.

## Nunca no GitHub

- outputs reais de clientes;
- inventários reais;
- credenciais, tokens, chaves e certificados privados;
- logs contendo dados confidenciais;
- documentos comerciais/contratuais que não sejam necessários à engenharia;
- backups do Drive.

## Nunca no Drive como fonte editável principal

- cópia paralela do código em desenvolvimento;
- rulesets editados manualmente fora do GitHub;
- documentação técnica que precise acompanhar exatamente cada commit.

Pacotes de release no Drive são snapshots imutáveis, não fonte de desenvolvimento.

## Fluxo de mudança

1. Issue/decisão técnica no GitHub.
2. Branch `feature/`, `fix/`, `chore/`.
3. Implementação + testes.
4. Pull Request.
5. CI/revisão.
6. Merge em `main`.
7. Tag/release quando houver baseline relevante.
8. Evidência de LAB/aceite e artefatos formais são arquivados no Drive.
9. Documentos de governança/status no Drive apontam para a release/tag correspondente.

## Regra para o P01

- GitHub: software vivo.
- Drive: empresa, produto, evidência e entrega.
