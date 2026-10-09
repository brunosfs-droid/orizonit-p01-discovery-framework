# Cancã v0.6.44 — revisão estrutural privada da auditoria

Incremento R02/R06 sobre v0.6.43, PR #155. O módulo
`server/P01_Workspace_Audit_Review.py` valida o JSONL do FileAudit workspace
sem alterar registros. Não executa coleta nem concede autorização operacional.

## Contrato

`validate(bytes)` exige arquivo não vazio de até 8 MiB, terminado por LF,
registros ASCII de até 1024 bytes incluindo LF e campos exatos por evento.
Rejeita campos duplicados/desconhecidos, NaN, datas inválidas, operações fora
do catálogo, status booleano, identidade inválida e workspace sem operador.
Sequência começa em 1; listener inicia uma única vez; no máximo oito pedidos
ficam pendentes. IDs não podem ser reutilizados nem depois de concluídos.
Fim de requisição deve corresponder ao início; fim de listener exige todos
os pedidos concluídos e não admite eventos posteriores.

Um prefixo aberto com linhas completas retorna contagem de pedidos pendentes
para análise de recuperação. Cauda truncada é inválida; não é reparada ou
ignorada. `listener_closed` distingue encerramento normal de prefixo aberto.
`execution_authorized=false` e `integrity_proven=false` são invariantes.
A saída e o erro `audit_journal_invalid` não reproduzem campos privados.

`validate_file(path)` reutiliza o leitor de snapshot privado já existente
em `P01_Operator_Audit_Check`: leitura limitada, identidade e metadados
antes/depois, arquivo regular exclusivo, rejeição de links/reparse points,
verificação do diretório e permissões POSIX. Revisar cópia privada estável
ou arquivo de listener encerrado; mutação observada durante leitura falha.
Isso não substitui ACLs Windows nem prova autenticidade contra um agente
capaz de reescrever o arquivo e seus metadados.

## Validação reproduzível

Na raiz do repositório:

```sh
python -m unittest discover -s tests -p 'test_workspace_audit*.py' -v
python -m unittest discover -s tests -p 'test_operator_audit_check.py' -v
```

Os sete casos do novo módulo cobrem produtor real, preservação dos bytes,
replay, campos/tipos, capacidade, prefixo pendente e entradas privadas
inválidas. Python CI descobre a suíte; Workspace Foundation CI a executa
explicitamente nas matrizes PostgreSQL 16/17. Esta suíte é local/arquivo;
não se atribui a ela persistência SQL ou homologação EVE-NG.

## Próxima etapa e recuperação

O journal continua sendo evidência privada por listener, não um ledger de
aprovação. Nunca reconstruir concessões ou retomar scanners a partir dele.
Preservar arquivo original em caso de falha, revisar snapshot privado e
correlacionar pedidos incompletos com estado transacional antes de qualquer
retomada controlada. Um novo listener usa arquivo exclusivo novo.

Próximo incremento: definir persistência transacional de intenções e decisões
com identidade do aprovador, workspace, geração, escopo/digest, validade,
consumo único e revogação. Separar registro de decisão de execução; falhas
entre commit, auditoria e consumo devem ter contraprovas de recuperação e
não produzir autorização implícita. Migração, retenção e integração ao
executor exigem contratos e testes próprios antes de habilitar AUTH/FULL.

R02/R06 permanecem parciais; E0, contenção Windows/remota e credenciais
isoladas continuam pendentes. Esta entrega não fecha Product Alpha.
