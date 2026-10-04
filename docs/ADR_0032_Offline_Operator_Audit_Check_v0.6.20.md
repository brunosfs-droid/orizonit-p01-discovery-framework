# ADR 0032 — revisão offline da auditoria de operadores

Data: 04/10/2026 (-03). Decisão de implementação: aceita.
Classificação: A — MVP, diagnóstico operacional. Qualificação operacional: CANDIDATE.
Base: `000c1a72179ffdc35b22869e7fa8d0907c545f58`.

## Contexto

A auditoria opcional v0.6.19 preserva o arquivo ao falhar ou ser interrompida.
Um início sem fim ou uma última linha sem newline não devem ser confundidos com
encerramento normal. Falta uma revisão local que descreva esse estado sem expor
identificadores privados nem editar o prefixo observado.

## Decisão

- CLI stdlib somente leitura, separada do listener e do collector. Recebe um
  arquivo privado regular, sem aliases/UNC/hardlinks, até 8 MiB. Confere identidade,
  tamanho, metadados e privacidade antes/depois da leitura; drift observado nega
  a revisão. Nenhuma abertura em modo de escrita, reparação ou exclusão.
- Verifica o formato audit_version 1 de forma independente do produtor: campos
  exatos, tipos, UTC, sequência, listener constante, eventos/labels fixos e pares
  por request_id. No máximo oito requests abertos; encerramento exige zero pares
  pendentes. Rejeita JSON duplicado, tipos permissivos, eventos/IDs reutilizados
  e registros depois de listener_stopped.
- Exige ao menos listener_started completo. Uma única última linha sem newline
  de até 1023 bytes pode permanecer não interpretada após o prefixo válido,
  desde que o listener não tenha sido encerrado. Não atesta validade dessa cauda.
  Erro em qualquer linha completa é inválido, não é ocultado como interrupção.
- Saída fixa com SHA256 de todos os bytes observados, tamanho, estado, contagens
  de eventos/operações/outcomes/classes HTTP e número de requests sem fim.
  Nenhum ID de operador/assessment/request, timestamp, path, linha ou erro bruto.
  SHA esperado opcional cerca a revisão de um snapshot previamente identificado.
- Exit 0: estrutura encerrada; exit 3: prefixo válido aberto/com cauda parcial;
  exit 2: entrada/leitura/estrutura inválida ou hash divergente. Saída prefixo
  nunca se apresenta como execução encerrada. Erros são códigos fixos em JSON.
- HTTP/auditoria/contas e os formatos de relatório não mudam. Fixtures de CI
  podem revisar o arquivo temporário depois de fechar o servidor, mantendo as
  conferências independentes anteriores de ausência de segredos/isolamento.

## Limites

Estrutura válida e hash não provam autoria, autorização real dos IDs, integridade
contra administrador hostil, fsync durável, recebimento pelo cliente ou cobertura
de eventos anteriores ao handler. O prefixo pode ser de execução ainda ativa ou
interrompida; a ferramenta não escolhe entre elas. Relógio regressivo é permitido,
pois sequence define a ordem. O SHA inclui a cauda que não foi interpretada.

Sem rotação, retenção, SIEM, endpoint/tela, reaproveitamento de arquivo, scanner,
SQL, store ou dependência de teste manual. Windows requer ACLs futuras próprias.
Collector portable permanece sem login; credenciais de alvo e mTLS separados.
CI nativo Linux/Windows, interrupção real em subprocesso, HTTP/Chromium e reader
PostgreSQL sintéticos verificam o incremento sem alteração do LAB aprovado.
