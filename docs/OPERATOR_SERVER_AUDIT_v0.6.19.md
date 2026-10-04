# Auditoria opcional do servidor de operadores v0.6.19

Status: CANDIDATE operacional. Implementação/CI independente do LAB.
Componente de auditoria v0.6.19, formato `audit_version=1`.
Web/conteúdos v0.6.17, API/Auth v0.6.11 e política de contas v1 preservados.

## Uso e aplicação futura

O listener de operadores pode registrar suas operações em JSONL privado. O
default continua sem arquivo de auditoria; para uma implantação nova/controlada,
informe um nome novo por execução:

```sh
python server/P01_Operator_Web.py --accounts /etc/canca/operator-accounts.json --host 127.0.0.1 --port 8878 --audit-file /var/lib/canca/operator-audit/server-20261004-01.jsonl
```

O entry point `server/P01_Operator_API.py` aceita a mesma opção. Este exemplo não
é um passo de LAB solicitado hoje: não iniciar/reiniciar o serviço aprovado ou
alterar contas reais para qualificar este código. Sem `--audit-file`, comportamento
e saídas anteriores são preservados. Não há tela/endpoint para acessar os logs.

O diretório deve existir e ser privado/controlado: 0700 recomendado em POSIX,
owned pelo usuário atual ou root; arquivo novo exclusivo 0600. Symlinks/aliases,
UNC, nomes existentes e arquivos com hardlinks são rejeitados. Em Windows,
configure ACLs restritivas explicitamente: mode POSIX não prova ACL de implantação.
O registro pode conter IDs corporativos autorizados; trate o arquivo como privado.

## Eventos e campos

Cada linha é um objeto JSON independente, com newline, até 1024 bytes. Timestamps
UTC refletem o relógio do host; `sequence` define a ordem serializada no arquivo,
mesmo sob requests concorrentes. Versão, sequência, UTC, `listener` (api/web) e
`event` aparecem em todos os registros.

| Evento | Campos específicos | Significado |
| --- | --- | --- |
| listener_started | nenhum | Registro aberto durante a construção do listener; não atesta prontidão do banco |
| request_started | request_id, operation | Início gravado/fsync antes de executar o handler |
| request_finished | request_id, operation, http_status, outcome, operator_id, assessment_id | Resultado do handler/escrita no socket e IDs autorizados, ou null |
| listener_stopped | nenhum | Encerramento após os workers; arquivo não será reutilizado |

`request_id` é aleatório, gerado pelo servidor, sem derivação do token. O status
HTTP é o último preparado pelo servidor ou null se não houve resposta; não prova
o status recebido pelo cliente. `outcome` é `response_written`, `delivery_failed`
ou `handler_failed`. Escrita concluída no socket não comprova recebimento,
integridade, salvamento ou leitura do download no computador do operador.

| operation | Origem no handler |
| --- | --- |
| login / logout | Criação/revogação da sessão local |
| assessment_directory | IDs permitidos pela política da própria sessão |
| report_page | Consulta técnica paginada |
| executive_preview | Resumo executivo autorizado |
| technical_export / executive_export | Downloads completos |
| public_asset / health | Shell/assets públicos e health encaminhados ao handler |
| other | Outra rota/método encaminhado ou route hint não classificável |

O rótulo descreve a rota tentada; não significa que ela foi autenticada ou aceita.
`operator_id` vem apenas do login concluído ou de sessão validada; tentativas
desconhecidas/desabilitadas ou origem negada não copiam o username submetido.
`assessment_id` é gravado somente depois de validar o grant exato. Negações não
copiam o ID arbitrário solicitado; o diretório não grava a lista completa de grants.

Nunca são copiados senha/salt/hash, token/hash de token, username submetido, IP
de cliente, headers, body, URL/query/cursor, caminho local, DSN/erro bruto,
conteúdo de relatório/evidência, referências de ocorrência ou Secret Provider.
Conta/assessment são metadados já autorizados, não resultado de detecção de segredo.

## Limites, falhas e encerramento

Máximo **8 MiB por execução**, oito requests simultâneos e um lock para sequência/
escrita. O início reserva 1024 bytes para o fim de cada request admitido e para
o encerramento. Ao atingir o orçamento, novos requests recebem **503** com
`operator_audit_unavailable`; os já admitidos mantêm sua reserva. Não há rotação,
compressão, purge, append de arquivo anterior, retry ou envio para outro serviço.
O orçamento técnico opt-in pode negar acesso legítimo; não é quota de edição.

Cada append confere descriptor, regularidade/identidade, tamanho/metadados,
hardlinks e privacidade do diretório/arquivo. Flush/fsync precede o trabalho;
POSIX também sincroniza o diretório na abertura/fechamento. Alteração observada
ou falha de I/O invalida o sink: requests posteriores são negados antes de login,
logout, SQL ou download. Corrigir o arquivo em execução não libera o sink.

Falha no registro final pode ocorrer após a resposta já ter sido enviada; não
é possível desfazer uma consulta, revogação ou informação entregue. O início
permanece no prefixo observado e nenhum resultado é fabricado para completar
a trilha. Outros requests já admitidos podem terminar; novos são negados.

Encerramento normal aguarda os workers e fecha o descriptor. Falha no registro
de encerramento retorna código fixo/exit 2 na CLI. Interrupção abrupta pode deixar
início sem fim, linha parcial/completa sem confirmação de fsync ou ausência de
listener_stopped. Não editar/reaproveitar o arquivo para esconder esse estado:
preserve-o para revisão e escolha outro nome em um reinício controlado futuro.
Startup que falha pode deixar um arquivo privado novo; não é apagado sozinho.

## Escopo e qualificação

A cobertura é de GET/POST/DELETE encaminhados após parsing HTTP e admissão do
worker/TLS. Handshake recusado, saturação antes do handler, erro do parser,
método não encaminhado ou listener que não iniciou podem não gerar evento.
Essas fronteiras requerem logs próprios de OS/rede/proxy em implantação futura.

Não é log imutável, assinatura, prova de autoria, SIEM, HA, política de retenção
ou defesa contra o dono hostil do filesystem. A checagem detecta drift observado;
um administrador que controla o host pode editar/remover arquivos. IDs/dados
reais nunca vão para Git. Os arquivos sintéticos do CI são temporários.

CI nativo Linux/Windows, HTTP real e PostgreSQL SELECT-only verificam isolamento,
concorrência, limites, falhas/interrupção e invariância de banco/store. Chromium
usa o registro privado opt-in; ZIPs/JSON/PNG anteriores mantêm seus contratos.
Gates operacionais de ACL, retenção, restart, TLS/roles completos e LAB são
independentes e não solicitados neste incremento.

Collector portable continua sem login Cancã; credenciais dos alvos, mTLS de Node,
política/revisões offline e artefatos do assessment permanecem separados.

[ADR 0031](ADR_0031_Operator_Server_Audit_v0.6.19.md) ·
[Qualificação](validation/OPERATOR_SERVER_AUDIT_CI_v0.6.19.md) ·
[Servidor](../server/README.md).
