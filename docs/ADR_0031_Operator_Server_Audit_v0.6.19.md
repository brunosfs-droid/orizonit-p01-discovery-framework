# ADR 0031 — auditoria opcional do servidor de operadores

Data: 04/10/2026 (-03). Decisão de implementação: aceita.
Classificação: A — MVP. Qualificação operacional: CANDIDATE.
Base: `b59e26a3583263f7f0e6032bca31e09e2e3eef4e`.

## Contexto

O servidor já separa contas humanas, grants de assessment e mTLS dos Nodes.
Seus handlers suprimem logs HTTP genéricos para não expor credenciais, URLs ou
erros de backend. Falta um registro operacional local com campos controlados
para acompanhar o uso dessa fronteira sem copiar relatórios/evidências.

## Decisão

- Auditoria opt-in por `--audit-file`, independente da política de contas e do
  banco. Default desativado; respostas e versões de conteúdo Web/API preservadas.
- Um arquivo JSONL novo por execução do listener; nunca anexar/sobrescrever um
  nome existente. Diretório privado/controlado, arquivo regular exclusivo 0600
  em POSIX; ACL Windows é responsabilidade da implantação futura.
- Registros de início/fim do listener e início/fim de requests GET/POST/DELETE
  encaminhados aos handlers existentes. Operações são rótulos fixos, não URLs.
  Cada request recebe ID aleatório próprio, sem derivação de bearer token.
- Campos explícitos: versão, sequência, timestamp UTC, tipo de listener/evento,
  ID/operação do request, status HTTP e resultado da escrita. IDs de operador
  vêm somente da sessão autenticada ou login concluído; ID de assessment somente
  de grant autorizado. Negação não copia o ID arbitrário solicitado.
- Nunca gravar username submetido, senha/salt/hash, token/hash de token, IP de
  cliente, headers, body, query/cursor, URL, path local, DSN, erro bruto, dados do
  relatório, grants completos ou referências de evidência/Secret Provider.
- Formato limitado a 1024 bytes por registro e 8 MiB por arquivo. Lock de thread
  serializa sequência/escrita; início de request reserva espaço para seu fim e
  para encerramento. Sem rotação, compressão, exclusão ou envio automático.
- Flush/fsync antes de admitir o trabalho de cada request. Se o arquivo estiver
  indisponível, cheio, alterado ou com metadados privados divergentes, negar novo
  trabalho com 503 e código fixo `operator_audit_unavailable`. Não executar login,
  revogação, consulta ou download quando o início não puder ser registrado.
  O limite nega novos inícios e conserva a reserva dos requests admitidos e do
  encerramento; falha de I/O/drift invalida também futuras escritas na instância.
- Fim de request descreve a escrita no socket pelo servidor, não recebimento ou
  salvamento pelo cliente. Falha no registro final pode ocorrer depois da resposta;
  preservar o prefixo e bloquear requests futuros. Não desfazer operação/SQL nem
  fabricar resultado de auditoria para ocultar a falha.
- Encerramento aguarda workers antes de fechar o registro. Interrupção abrupta
  pode deixar requests sem fim, linha parcial ou ausência de fim do listener.
  Arquivos anteriores ficam preservados; restart exige outro nome explícito.

## Fronteiras e consequências

O registro cobre a aplicação após parsing HTTP, admissão de worker e handshake
TLS. Conexões recusadas, erros do parser, métodos não encaminhados e falhas antes
do handler não constituem eventos desta versão. Não é SIEM, trilha imutável,
assinatura/autoria, mecanismo de retenção, revisão de contas ou substituto de
logs de firewall/proxy/OS. O dono hostil do filesystem não é uma fronteira
protegida; verificações detectam alterações observadas entre escritas.

O orçamento opt-in pode negar acesso legítimo e requer encerramento/revisão do
arquivo e novo nome em reinício controlado. R1/soaks aprovados, ZIPs e síntese
canônicos permanecem preservados; nenhum novo teste de LAB é solicitado.
Collector portable continua sem login Cancã; alvos/credenciais/mTLS permanecem
separados. Sem migração, escrita SQL, store, AD/SSO, inventário ou mapper.

CI sintético Linux/Windows cobre o filesystem nativo, requests HTTP reais,
isolamento/redação, concorrência, limites, drift, fsync e interrupção. Não aprova
ACLs, retenção ou troca operacional de produção; código e prova medidos serão
registrados antes da integração.
