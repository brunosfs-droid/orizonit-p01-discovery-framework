# Cancã — roteiro reproduzível E0 e recuperação isolada R1

Status: **roteiro pronto, LAB não executado**. Requisitos R01–R06 continuam parciais.
Base de planejamento: `docs/TEST_PLAN_1.0.md` (E0, T01–T07/T13) e
`docs/validation/ALPHA_R01_R06_GATE_MATRIX_2026-10-08.md`.

## Regras obrigatórias

1. Utilizar somente cluster/banco de ensaio **descartável**, com autorização do operador.
   Os harnesses `tests/workspace_backup_restore_smoke.py`,
   `tests/postgres_backup_restore_smoke.py` e suítes SQL opt-in podem apagar schemas:
   **não executá-los no LAB existente**.
2. Não fazer drop, clean, overwrite, restore, set role, mudança de grants ou
   `prepare-restored` até conferir e registrar identidades exatas de origem/destino,
   janela de quiesce e backup íntegro. Não executar restore no cluster de origem.
3. PostgreSQL16/17: pin de commit, schema9, configurações efetivas e roles explicitamente
   autorizadas. SQL e variáveis de libpq usam secret provider/.pgpass/PGPASSFILE privados,
   jamais DSN com senha na linha de comando, logs ou Git.
4. EVE-NG: reutilizar P01-MGMT01/DC01/W11/Rocky/Ubuntu onde disponíveis;
   ligar somente rodada E0. Evidências reais privadas (OneDrive restrito);
   somente relatório sanitizado no repositório.
5. As rotinas abaixo são **passos distintos**: captura e verificação offline são
   não destrutivas; provisionamento/restauração requerem aprovação humana antes da execução.
   O novo helper **não** verifica validade lógica do dump, RLS, roles, TLS ou dados pós-restore.

## Fase A — identificação da execução, sem escrita

No checkout do repositório no host de controle:

```bash
git status --short
git rev-parse HEAD
python3 --version
hostnamectl
ip -br address
ip route
timedatectl
df -h
psql --version
pg_dump --version
pg_restore --version
python3 -m unittest discover -s tests -p 'test_alpha_e0_recovery_preflight.py' -v
```

Registrar hostname, interfaces/rotas, relógio, espaço, versão de PostgreSQL, SHA
e escopo do LAB. Se o Git checkout contiver alterações não revisadas, não fazer
`git pull`/checkout destrutivo. Antes de conectar a origem, decidir quem pode ler
o store, exportar globals e copiar configuração/TLS sem violar permissões.

## Fase B — isolamento e preparação E0

- Conferir existência e disponibilidade de duas bases/workspaces A/B independentes;
  mesmos nomes/IP/IDs de teste devem permanecer separados.
- Reutilizar fixtures e contratos dos testes `test_postgres_workspace.py`,
  `test_workspace_coordinator.py`, `test_workspace_model.py`,
  `test_workspace_legacy.py` e `test_workspace_api.py`.
  **Essas suítes não são comandos para execução direta em bancos persistentes**.
- Isolar rede/coletas live: sem scanner, AUTH, FULL, upload ou service timer ativo.
  Capturar registro de jobs/leases e o estado `closed` após quiesce.
- Executar manualmente T01: A com grant e B sem grant; SELECT/HTTP B devem negar,
  e stores/receipts/IDs de B não podem aparecer em A. Capturar logs redigidos.
- Executar T02/T04/T05/T07 em clone descartável: parent/site cross-base recusado;
  migration exige mapping explícito; import mesmo bundle idempotente; drift
  revision-fenced, conflito de identidade sem overwrite; evidência e hashes iguais.
- T03: fechar workspace durante job controlado e processo desconectado, verificar
  cancelamento/reconciliação e nenhuma retomada automática de acesso live.
  Registrar adaptadores legados ainda não disponíveis como SKIP/bloqueio, não PASS.
- T06: qualificar somente grafo/ownership backend existente; Mapper/UI são gate v0.7.

## Fase C — captura consistente, após autorização de quiesce

Executar **apenas na origem aprovada** e com todos os writers/jobs pausados. Este
exemplo exige que a origem seja um banco de ensaio, não o banco operacional.
O operador preenche caminhos privados atuais, `PGDATABASE`, roles e TLS;
não publicar o conteúdo dessas variáveis.

```bash
umask 077
export E0_PRIVATE=/var/lib/canca/alpha-e0-proof
export E0_SOURCE_STORE=/CAMINHO/PRIVADO/STORE-ORIGEM
export E0_CONFIG_ROOT=/CAMINHO/PRIVADO/CONFIG-ORIGEM
export PGDATABASE=canca_alpha_e0_source
: "${E0_SOURCE_STORE:?}" "${E0_CONFIG_ROOT:?}" "${PGDATABASE:?}"
install -d -m 700 "$E0_PRIVATE" "$E0_PRIVATE/store-snapshot" \
  "$E0_PRIVATE/config-snapshot" "$E0_PRIVATE/proof"
# Confirmar o target e o estado quiescent em registro de mudança ANTES do dump.
pg_dump --format=custom --file="$E0_PRIVATE/database.dump"
pg_dumpall --globals-only --file="$E0_PRIVATE/globals.sql"
cp -a -- "$E0_SOURCE_STORE"/. "$E0_PRIVATE/store-snapshot"/
cp -a -- "$E0_CONFIG_ROOT"/. "$E0_PRIVATE/config-snapshot"/
pg_restore --list "$E0_PRIVATE/database.dump" > /dev/null
python3 docs/validation/ALPHA_E0_RECOVERY_PREFLIGHT.py capture \
  --database-dump "$E0_PRIVATE/database.dump" \
  --roles-snapshot "$E0_PRIVATE/globals.sql" \
  --store-root "$E0_PRIVATE/store-snapshot" \
  --config-root "$E0_PRIVATE/config-snapshot" \
  --output "$E0_PRIVATE/proof/manifest.json"
sha256sum "$E0_PRIVATE/proof/manifest.json"
```

Saída esperada do helper: `{"gate":"ALPHA_E0_ARTIFACTS",...,"status":"CAPTURED"}`,
exit 0. Não usar `pg_dumpall --globals-only` sem autorização de administrador:
pode conter hashes de senhas das roles. Os snapshots privados podem conter chaves TLS.
Manter diretórios mode0700, manifest0600, nunca commitar, enviar em canal público,
copiar para workspace não autorizado ou embutir no relatório.

O helper captura **SHA256 dos bytes** de dump/globals e um hash ordenado de
caminhos relativos, bytes e permissões da árvore de store e configuração,
publicando somente digests/contagens. Detecta symlinks e alterações em trânsito,
mas não fornece assinatura criptográfica nem snapshot atômico entre PostgreSQL e
filesystem. **Quiesce e conferência do par são obrigatórios.**

## Fase D — transferência/verificação independente

Transferir os quatro componentes (database.dump, globals.sql, store-snapshot,
config-snapshot) e o manifest por canal autorizado, mantendo permissões e os
dados privados; o path destino é escolhido pelo operador. Em ambiente de destino
isolado, com o mesmo checkout/commit aprovado:

```bash
export E0_TRANSFER=/CAMINHO/PRIVADO/TRANSFERENCIA
python3 docs/validation/ALPHA_E0_RECOVERY_PREFLIGHT.py verify \
  --database-dump "$E0_TRANSFER/database.dump" \
  --roles-snapshot "$E0_TRANSFER/globals.sql" \
  --store-root "$E0_TRANSFER/store-snapshot" \
  --config-root "$E0_TRANSFER/config-snapshot" \
  --manifest "$E0_TRANSFER/proof/manifest.json"
pg_restore --list "$E0_TRANSFER/database.dump" > /dev/null
sha256sum "$E0_TRANSFER/proof/manifest.json"
```

`status=PASS` significa **integridade offline dos artefatos transferidos**,
não restauração nem funcionamento do Cancã. `FAIL`/exit2 bloqueia a rodada.
Conferir também o hash do manifest com registro assinado/confiável da origem:
o arquivo manifest **não tem assinatura**, logo sua adulteração conjunta com os
artefatos não é detectada pelo próprio helper.

## Fase E — restore em outro cluster (hold point explícito)

Após A–D PASS, o operador deve apresentar para aprovação: identificação do cluster
de destino **diferente do original**, versão major, banco destino **inexistente**,
roles existentes/planejadas, domínio TLS/certificados, impacto de importar globals,
parâmetros de serviço e rollback. Não automatizar CREATE/DROP/restore neste roteiro.

Sequência de execução aprovada pelo DBA, em destino descartável e vazio:

1. Provisionar cluster separado com versões/extensões compatíveis e material TLS
   privado; reconciliar `globals.sql`/roles/grants com contas e privilégios já
   existentes. **Nunca aplicar cegamente globals em um cluster compartilhado**.
2. Criar um banco destino novo e vazio sob owner revisado; restaurar com
   `pg_restore --single-transaction --exit-on-error` sem flags que silenciosamente
   descartem grants/ownership; validar código de saída e lista de objetos.
3. Restaurar o store e configurações em paths privados revisados; conferir ACLs,
   ownership, configuração do serviço, referências externas, secret providers e
   certificados; deixar listeners/coletas desabilitados inicialmente.
4. Conferir contagens/revisões, RLS forçada, grants, usuários A/B e relatórios/receipts.
   Falha de TLS/roles, linhas órfãs, checksum divergente ou acesso B indevido = FAIL.
5. Com maintenance identity legítima e coordenador **parado**, executar apenas
   `python persistence/P01_Workspace_Recovery.py inspect` inicialmente. Se o
   conjunto DB/store/config/roles foi validado e a generation registrada é a esperada,
   aprovar separadamente `prepare-restored --expected-generation N`.
6. Abrir A, comprovar que tokens/leases anteriores foram invalidados e que nenhuma
   autenticação/coleta antiga reinicia automaticamente; abrir B somente depois de
   fechar A. Revalidar replay/receipts, relatório e audit redigida.
7. Medir RTO desde início de recuperação até serviço testado, RPO pela idade da
   última evidência/transaction consistentes; não inferir objetivo cumprido apenas
   por duração de um fixture.

## Fase F — aceite e atualização do backlog

Para cada T01–T07/T13: `case_id | SHA | host/DB major | expected |
observed | PASS/FAIL/SKIP | evidence SHA256 | limitation | approver`.

- **PASS** requer prova positiva e negativa, inclusive ACL/RLS após restore.
- **SKIP** identifica ausência de adapter/vendor/cenário; nunca vira PASS implícito.
- **FAIL** bloqueia gate; corrigir em branch com nova qualificação, preservar evidências.
- **R06 / issue #63** só podem encerrar depois de R01–R05 e recovery operacional
  aprovados no escopo da Alpha. R20/GA, E1–E7, Mapper e vendors seguem independentes.

Arquivos de saída do LAB e globals/chaves permanecem privados; relatórios públicos
contêm apenas critérios, resultados e hashes sanitizados.
