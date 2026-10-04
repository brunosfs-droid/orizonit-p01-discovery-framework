# Revisão offline da auditoria de operadores v0.6.20

Status: CANDIDATE operacional. CLI stdlib somente leitura; formato audit_version 1
e produtor v0.6.19 preservados. Desenvolvimento/CI independente do LAB.

## Uso em uma revisão futura

```sh
python server/P01_Operator_Audit_Check.py --audit-file /var/lib/canca/operator-audit/server-20261004-01.jsonl
```

Para conferir um snapshot previamente identificado, acrescente
`--expected-sha256` com seu SHA256 completo de 64 caracteres hexadecimais minúsculos.
Hash divergente falha antes de interpretar os registros. O hash é de todo o arquivo,
incluindo uma possível cauda não interpretada; não é assinatura nem hash de senha.

O arquivo e o diretório devem ser privados/controlados, sem aliases, symlinks,
UNC ou hardlinks. Arquivo regular, até 8 MiB; POSIX exige proprietário atual/root
e nenhum acesso para grupo/outros, com 0600/0700 recomendados. Windows exige
ACLs restritivas próprias na implantação futura. A leitura confere identidade,
metadados/tamanho e privacidade antes/depois; mudança observada retorna erro fixo.
Um log ainda em atividade pode mudar durante a leitura e ser rejeitado.

Não precisa iniciar o servidor, autenticar operador, abrir PostgreSQL ou acessar
o store. Não modifica bytes, nomes ou permissões, cria saída em disco, completa
pares, apaga cauda ou reaproveita o arquivo. Leitura comum pode atualizar atime
no filesystem. Este exemplo não é um novo passo de LAB solicitado hoje.

## Resultados e códigos de saída

Cada execução escreve um objeto JSON no stdout, sem path, IDs de
request/operador/assessment, timestamps ou linhas de entrada. A saída tem campos
fixos e contagens, não uma cópia redigida de todos os registros.

| Exit | status | state | Significado |
| --- | --- | --- | --- |
| 0 | closed_structure | closed | Registros completos e pareados, encerramento final presente |
| 3 | valid_prefix | open_prefix | Prefixo válido, sem encerramento; pode haver requests sem fim |
| 3 | valid_prefix | partial_prefix | Prefixo válido com última linha sem newline; cauda não interpretada |
| 2 | failed | ausente | Entrada/leitura/estrutura inválida ou SHA divergente |

Os códigos de erro possíveis são operator_audit_input_invalid,
operator_audit_read_failed, operator_audit_structure_invalid e
operator_audit_digest_conflict. Nunca contêm texto submetido ou exceção bruta.
Flags desconhecidas, abreviadas, repetidas ou obrigatórias ausentes falham sem eco.

A saída inclui version, audit_version, audit_sha256, size_bytes, listener,
valid_records, partial_tail_bytes, unfinished_requests e quatro grupos de contagens:

- events: início/fim do listener e início/fim dos requests;
- operations: started/finished para os dez labels fixos do produtor;
- outcomes: response_written, delivery_failed e handler_failed;
- http_classes: 1xx a 5xx e none para os fins observados.

Negações 4xx/5xx são contabilizadas por classe; não se presume causa específica.
O status HTTP é o último preparado no servidor, não comprova entrega. Contagens
de operation descrevem a rota tentada, não sua autorização ou sucesso. Nenhuma
estatística identifica usuários/assessments ou calcula risco de infraestrutura.

## Formato e interrupção

Verificação independente do produtor: campos exatos, tipos estritos, JSON sem
chaves repetidas/NaN, IDs sintaticamente válidos, UTC com microssegundos, sequência
contígua, listener constante, labels/outcomes conhecidos e pares pela mesma
operação/request_id. IDs de request repetidos são rejeitados. No máximo oito
requests abertos; listener_stopped exige zero pendentes e deve ser o último evento.
O relógio pode recuar; sequence continua definindo a ordem observada.

Uma última linha sem newline, de até 1023 bytes, pode ser ignorada **somente depois
de listener_started completo e antes de listener_stopped**. Mesmo um objeto JSON
completo sem newline não é contado. A cauda não é declarada válida e seus bytes
entram no hash/tamanho total. Uma linha completa inválida, interna ou final,
falha com exit 2. Arquivo vazio ou início sem nenhum registro completo também
não contém um prefixo verificável e falha.

Um início sem fim pode representar request ativo, interrupção ou falha de registro.
A ferramenta não escolhe a causa, inventa seu resultado nem altera o arquivo.
Encerramento ausente continua aberto mesmo quando todos os pares observados
estão completos. Uma linha escrita antes de fsync falho pode ser completa e
legível; revisão estrutural não comprova persistência durável.

## Qualificação e limites

Testes sintéticos usam registros independentes inválidos, arquivos reais
Linux/Windows, drift, corrupção, capacidade, saída abrupta em subprocesso e
servidor HTTP real. Chromium revisa o arquivo temporário depois de fechar o
listener, conservando checagens independentes de privacidade. PostgreSQL
SELECT-only verifica o prefixo sem fim após fsync falho, com invariância de
14 tabelas e hashes do store. JSONL temporário não integra artefatos públicos.

Hash/estrutura não comprovam autoria, autorização real dos IDs, inviolabilidade,
recebimento/salvamento pelo cliente nem todos os eventos do servidor. Um arquivo
fabricado estruturalmente compatível pode passar. O proprietário hostil do host
não é uma fronteira protegida. O relatório descreve somente os bytes estáveis
observados na leitura, sem congelar o arquivo ou acompanhar mudanças posteriores.

Sem endpoint/tela, SIEM, rotação, retenção, recuperação automática, alteração de
contas, SQL de escrita, coleta ou implantação. R1/soaks aceitos e gates manuais
adiados permanecem independentes. Collector portable continua sem login Cancã;
credenciais de alvos e mTLS de Node permanecem separados.

[ADR 0032](ADR_0032_Offline_Operator_Audit_Check_v0.6.20.md) ·
[Registro de qualificação](validation/OPERATOR_AUDIT_CHECK_CI_v0.6.20.md) ·
[Produtor v0.6.19](OPERATOR_SERVER_AUDIT_v0.6.19.md).
