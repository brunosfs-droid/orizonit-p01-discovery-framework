# Administração local de operadores v0.6.18

Status: CANDIDATE operacional. Implementação/CI independentes dos testes manuais
adiados pelo mantenedor em 03/10/2026 (-03); nenhuma ação no LAB solicitada hoje.
[ADR 0030](ADR_0030_Offline_Operator_Accounts_v0.6.18.md) ·
[Registro CI](validation/OPERATOR_ACCOUNTS_CI_v0.6.18.md).

## Finalidade

`server/P01_Operator_Accounts.py` administra a política de contas humanas do
servidor, usando o formato v1 existente. A ferramenta permite inspecionar contas
e gerar uma revisão privada para adicionar um operador, substituir seus grants,
desabilitar/habilitar a conta ou trocar sua senha. Usa os mesmos identificadores,
validadores e scrypt do módulo de autenticação v0.6.11.

O arquivo de origem é preservado. Cada mudança exige seu SHA256 e um arquivo de
saída novo, que não pode existir. A ferramenta publica uma cópia validada e
informa que é necessário reinício controlado. Ela não recarrega a política nem
altera sessões de um listener em execução. Até o reinício, contas/grants/senhas
e tokens daquele processo continuam sujeitos à sua política imutável e TTL.

Não há endpoint de escrita, cadastro público, remoção/renomeação de operadores,
wildcard ou conta administradora implícita. Os IDs de operador/username existentes
são preservados. Grants são apenas `assessment:read`, por assessment exato e
sensível a maiúsculas/minúsculas; usernames seguem comparação case-insensitive.
Autenticação local do servidor, credenciais dos alvos e identidade mTLS do Node
mantêm seus papéis. O collector portable continua executando sem login Cancã.

## Comandos em uma implantação futura controlada

Estes exemplos documentam a ferramenta; não constituem um novo roteiro de LAB.
Use um diretório de configuração sob controle do administrador. Arquivos devem
ser regulares, privados e sem aliases/reparse points ou hardlinks. A ferramenta
rejeita UNC e diretórios com aliases. Em POSIX, o diretório de saída deve ser
privado (0700), e os arquivos são 0600. Em Windows, configure ACLs restritivas
explicitamente no diretório; mode 0600 não comprova uma DACL segura.

Inspeção somente leitura:

```sh
python server/P01_Operator_Accounts.py --policy /etc/canca/accounts-v1.json inspect
```

JSON inclui versão, SHA256 do arquivo completo, quantidade de contas e, por
operador, ID/username, enabled e IDs de assessments ordenados. Não exibe salt,
hash de senha ou senha. O `policy_sha256` é a cerca para uma revisão; não é um
hash de senha nem assinatura de autoria.

Use o hash real de 64 caracteres no lugar de `SHA256_DA_ORIGEM` e um novo nome
de saída por operação. Adição de conta com grants explícitos:

```sh
python server/P01_Operator_Accounts.py --policy /etc/canca/accounts-v1.json add --output /etc/canca/accounts-v2.json --expected-policy-sha256 SHA256_DA_ORIGEM --operator-id OP-02 --username second --assessment-id LAB-001 --assessment-id LAB-002
```

Adicionar ou trocar senha exige terminal interativo e dois prompts ocultos de
15–256 caracteres, mantendo espaços/Unicode e o limite UTF-8 existente. Senhas
não são aceitas em argumentos, stdin por pipe ou configuração por variável de
ambiente. Não há senha padrão. A adição rejeita operador duplicado ou username
já existente, inclusive com capitalização diferente.

| Operação | Parâmetros específicos | Resultado na revisão |
| --- | --- | --- |
| `add` | `--username`, `--operator-id`, um ou mais `--assessment-id`; senha em dois prompts | Nova conta habilitada com grants exatos |
| `set-grants` | `--username` e um ou mais `--assessment-id` | Substitui integralmente os grants da conta |
| `set-grants` | `--username --clear-grants` | Mantém login habilitado, sem leitura de assessments |
| `disable` / `enable` | `--username` | Altera apenas enabled, preservando senha e grants |
| `rotate-password` | `--username`; senha em dois prompts | Novo salt/hash, preservando enabled e grants |

Todas as operações de mudança também exigem `--output` e
`--expected-policy-sha256`. Sets vazios exigem `--clear-grants`; duplicatas,
wildcards, IDs inválidos e alterações de grants/enabled sem efeito falham.
O campo `--assessment-id` pode ser repetido, com no máximo 128 grants por conta.
Alterar grants não confirma a existência desses assessments no PostgreSQL.

Exemplo de desabilitação em uma revisão nova:

```sh
python server/P01_Operator_Accounts.py --policy /etc/canca/accounts-v1.json disable --output /etc/canca/accounts-disabled.json --expected-policy-sha256 SHA256_DA_ORIGEM --username reader
```

Após inspecionar a revisão e conferir seu SHA256, o administrador deve encerrar
admissão de pedidos, aguardar os pedidos em andamento e reiniciar o listener com
o arquivo escolhido em `--accounts`. Isso cria outra instância de autenticação
e invalida os tokens anteriores. A ferramenta não executa essa aplicação.

## Publicação, limites e falhas

Os limites técnicos permanecem: política de até 64 KiB, 128 contas e 128 grants
por conta. A validação usa o parser estrito existente, inclusive chaves
desconhecidas/duplicadas, scheme/salt/hash e permissões. Não há nova dependência,
migração, SQL, acesso ao store ou a alvos. Web permanece v0.6.17 e API v0.6.11.

A leitura usa descriptor, tamanho limitado, file metadata e identidade do caminho
para detectar alterações normais durante a leitura. A cerca é conferida antes de
pedir senha e novamente após a preparação, imediatamente antes da publicação.
Uma troca do inode da origem também interrompe a revisão, mesmo com bytes iguais.
A cerca não bloqueia um administrador/DBA nem ativa a revisão atomicamente.

Uma staging file privada recebe todos os bytes, flush/fsync e uma publicação por
hardlink exclusiva no mesmo diretório. Um arquivo concorrente de destino é
preservado. O staging é removido nas saídas ordinárias, e o diretório é sincronizado
em POSIX. Sistemas de arquivos sem hardlinks falham. Os testes usam o filesystem
nativo dos runners Linux/Windows, com hardlinks reais.
O CI não qualifica todos os sistemas de arquivos ou ACLs de implantação.

Interrupção do processo antes de publicar pode deixar um staging privado e nenhum
destino. Ele não é promovido, carregado nem removido automaticamente numa nova
execução. Após publicação, uma falha de sincronização/interrupção pode deixar uma
revisão completa com resposta de falha; inspecione explicitamente esse arquivo.
Não reutilize seu nome como destino de outra revisão. A origem e o listener atual
permanecem preservados em ambos os casos.

Sucesso de mudança: `status=revision_created`, versão da ferramenta/schema,
change, operador/username, quantidade de contas, hashes da origem/revisão,
`restart_required=true` e `live_sessions_updated=false`. Nenhuma credencial aparece
no JSON. Exit 0 é sucesso; exit 2 é falha com um destes códigos fixos:

| Código | Significado |
| --- | --- |
| `operator_policy_input_invalid` | Sintaxe/IDs/limites/operação sem efeito/senha/terminal inválidos |
| `operator_policy_read_failed` | Fonte privada inválida, aliases, hardlinks, tamanho/schema ou leitura em conflito |
| `operator_policy_base_conflict` | SHA ou identidade/metadata da fonte mudaram |
| `operator_policy_write_failed` | Saída existente/insegura, filesystem/publicação/sincronização falhou |

Erros não ecoam argumentos fornecidos ou exceções brutas, inclusive um `--password`
acidental. Nenhuma alteração de contas real, reinício de serviço ou validação de
AD/SSO é efetuada por este incremento. R1 aceitos e gates manuais adiados mantêm
seus pins e escopos.
