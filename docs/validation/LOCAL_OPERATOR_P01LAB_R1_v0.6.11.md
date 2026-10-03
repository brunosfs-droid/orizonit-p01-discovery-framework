# Cancã — aceite de operadores locais R1 v0.6.11

03/10/2026 (-03). **LAB VALIDATED**, limitado ao backend de operadores em
loopback no Rocky, base sintética recuperada `canca_p01_restore_r1`, assessment
`P01-PG-LAB-R1`. Código qualificado: `84437c8e6f0e6aa6976279ae26e1866cd123371a`
(PR #110, integrado em `e648523f26660d9e3ecf9e1f06c83d7d8a9bf138`).

## Evidência observada

Duas capturas enviadas por Bruno. A primeira mostra archive da revisão fixada,
envio por SCP, comparação SHA256 e `OPERATOR PACKAGE OK — persistencia aprovada
preservada`. O pacote novo está em `/root/p01/canca-operator-lab-v0.6.11`; o Python
e a persistência aprovados foram reutilizados do deployment v0.6.5.

A segunda mostra os parâmetros da base recuperada, execução do helper isolado,
`LOCAL OPERATOR LAB PASS`, quatro avaliações e
`OPERADORES VALIDADOS NESTA SESSAO: true`. São legíveis as negações sem sessão e
fora do assessment, logout, igualdade do relatório canônico, ausência de mutação
do banco/store, parada do servidor e remoção de credenciais temporárias. Também
aparece `unset PGPASSWORD` ao final.

O JSON está parcialmente cortado na horizontal. O aceite das 14 tabelas,
dois findings históricos, páginas fenced e página terminal vazia se apoia nas
asserções do helper qualificado que precedem a emissão de PASS. Não recebemos
relatório bruto, TAR, arquivo de contas ou acesso direto ao host; não alegamos
comparação independente desses bytes. O primeiro `ha256sum` foi um erro de
digitação corrigido para `sha256sum` na própria captura.

| Gate | Resultado |
| --- | --- |
| Instalação isolada / fontes verificadas | PACKAGE OK |
| Login local / consulta canônica | PASS |
| Sem sessão / assessment sem grant | Negado |
| Logout / token revogado | PASS |
| Quatro avaliações / dois findings históricos | Asserções do helper aprovadas |
| 14 tabelas / store | Sem mutação / sem acesso ao store |
| Servidor / contas temporárias | Parado / removidas |

## Limites

Não qualifica telas Web, HTTPS entre hosts, AD/SSO, MFA, HA, roles PostgreSQL
de produção, RBAC ampliado, produção ou principal de coleta. A role SELECT-only
tem qualificação CI separada; este R1 usa `canca_lab_admin` no destino sintético.
Collector portable permanece sem login Cancã; credenciais de alvos e mTLS do
Discovery Node têm finalidades independentes.

Não repetir este R1, restore, lifecycle ou exportação. O próximo incremento
é a consulta nas telas Web v0.6.12, sobre a mesma fronteira autenticada.

## Integridade das capturas

| Arquivo | SHA256 |
| --- | --- |
| image(20261003-031039).png | 358fd38065ab6fd6cd57acb3d543c0c76cb80e5184f1fe056d6078cb023bc74d |
| image(20261003-031324).png | 3f77dd89d4655e3cb1de5fd47091797c6f9b91157f2dc19446a5f1003b11dcb9 |

[ADR 0023](../ADR_0023_Local_Operator_API_v0.6.11.md) ·
[Roteiro histórico](../LAB_LOCAL_OPERATOR_R1_v0.6.11.md).
