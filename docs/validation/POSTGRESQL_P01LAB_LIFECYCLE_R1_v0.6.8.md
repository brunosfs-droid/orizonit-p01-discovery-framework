# P01 — aceite lifecycle/paginação R1 v0.6.8

02/10/2026 (-03). **LAB VALIDATED**, limitado à fixture sintética recuperada
canca_p01_restore_r1 / P01-PG-LAB-R1, Rocky/PostgreSQL 16.15.

## Evidência observada

Quatro capturas do operador, lidas integralmente. A localização automática encontra
uma referência única com SHA/sidecar aceitos; REFERENCIA EXISTE e RESTORED STORE
EXISTE aparecem. O caminho é derivado da referência, sem transcrever o sufixo aleatório.
Helper v0.6.8 instalado anteriormente do merge ec78a2bb5c08142aa197074c8797082dd61a3ae2;
correção do roteiro integrada pelo PR #104 (132afc598ad7c6eec9f6842062e47d673bc44b0d).

| Gate | Inspect | Primeiro exercise | Replay |
| --- | --- | --- | --- |
| Status | POSTGRESQL LAB PAGES PASS | POSTGRESQL LAB LIFECYCLE PASS | POSTGRESQL LAB LIFECYCLE PASS |
| Revisão inicial → final | 0 → 0 | 0 → 4 | 4 → 4 |
| Estado final | registered | completed | completed |
| Transições aplicadas | 0 | 4 | 0 |
| Cursores antigos rejeitados | 0 | 4 | 0 |
| Replays idempotentes | 0 | 4 | 4 |
| Conflitos negativos esperados | 0 | 3 | 3 |
| Páginas / avaliações | 4 / 4 | 4 / 4 | 4 / 4 |
| Findings registrados / CAS | 2 / 1 | 2 / 1 | 2 / 1 |
| Tabelas invariantes comparadas | 12 | 12 | 12 |
| Fontes revalidadas / store mutado | true / false | true / false | true / false |
| Lifecycle administrativo mutado | false | true | false |
| Exit capturado | PASS em JSON | 0 | 0 |

O primeiro exercise iniciou em registered/revisão 0 e demonstrou a sequência completa
até completed/revisão 4. O replay iniciou em revisão 4 e não aplicou transições,
não invalidou novos cursores e não duplicou eventos. Os dois exercícios saíram 0.
O helper aprovado também verifica histórico paginado, requests/actors fixos e findings Open.

Os JSONs resumidos mostram caminhos e hashes de três proofs privados no Rocky.
Recebemos as capturas, não os arquivos snapshot/sidecar nem dump. O aceite usa as
saídas do helper qualificado, sem alegar inspeção independente desses bytes.
As primeiras tentativas recovery_invalid permanecem registradas como falhas anteriores,
resolvidas pela localização automática; não foram transições nem restore adicional.

## Limites e próximo passo

completed é lifecycle administrativo: preserva os dois findings históricos Open e
não comprova remediação ou segurança do ambiente. Escopo: fixture sintética isolada,
conta proprietária no destino recuperado; não qualifica roles completos, TLS remoto,
RBAC de produto, disponibilidade/RTO/RPO ou produção. A referência original de 14 tabelas
é anterior às quatro transições intencionais; usar o comparador v0.6.8 para este gate.
Não repetir restore, instalação, inspect ou exercise para aprovar novamente este R1.

O desenvolvimento segue pela exportação consolidada somente leitura v0.6.9.
Finalizar a sessão de credencial do teste com `unset PGPASSWORD` quando não utilizada.

## Integridade das capturas

| Arquivo | SHA256 |
| --- | --- |
| image(20261002-230051).png | 9b084611557ee7d342c78a0075452cd08a76688f98b02e3f64e796816ab33752 |
| image(20261002-230214).png | 4d4b3db003a63f53ddc21ca493511ac5a294a8186c7c0f561d8fe7ae229e478d |
| image(20261002-230308).png | 06d0fb7238a1fedad4b63c1ccb7bc996fc0ae03d477d3c05ad87368248232f77 |
| image(20261002-230539).png | 3374eb39825c8bc230ee03e5559a1d85f1bbba758b4a1399a0138a2434c0b27c |
