# Cancã v0.6.94 — hardening do preflight R06 contra TOCTOU e symlink

## Vulnerabilidade endereçada

O helper offline `ALPHA_E0_RECOVERY_PREFLIGHT.py` validava um arquivo com `Path.lstat()` e depois o abria por nome via `Path.open()`. A origem poderia ser substituída por um symlink entre essas operações e, assim, o hash poderia inadvertidamente ler dados de outro arquivo. A conferência posterior de inode detectaria uma diferença, mas não impediria a **leitura indevida**.

## Mudança funcional

- `_open_source(path)` realiza, em POSIX com suporte a `dir_fd`, uma travessia por descritores: abre a âncora do caminho, percorre cada diretório com `O_DIRECTORY | O_NOFOLLOW` e, ao final, abre o arquivo com `O_NOFOLLOW` e `O_NONBLOCK` para evitar bloqueio acidental em um pipe/FIFO.
- Recusa componentes `..` / `.` na rota absoluta fornecida, sem seguir symlinks em diretórios intermediários ou no arquivo final.
- Compara `fstat()` do arquivo efetivamente aberto com o `lstat()` original **antes de ler bytes**, volta a comparar `fstat()` após o hash, e confirma `lstat()` do caminho depois da leitura.
- A identidade inclui `st_dev`, `st_ino`, tamanho, mtime em nanossegundos, ctime em nanossegundos e permissões. Falha de abertura, trocas detectadas e tipos especiais retornam erros genéricos e redigidos.
- O manifesto permanece apenas com hashes/tamanhos/contagens; o helper não executa SQL, restore, coleta ou conexão de rede.

## Plataformas e limites

**Proteção forte de travessia com descritores: POSIX com suporte a `O_NOFOLLOW` e `open(dir_fd=...)`.** Em Windows e plataformas sem essas primitivas, preservam-se as verificações pré e pós-abertura, mas **não é possível afirmar proteção equivalente contra corrida de symlink**. Usar artefatos imutáveis, diretórios controlados e homologação no Linux para aceite sensível R06. A checagem não garante consistência de snapshot de árvore mutável durante um `rglob` nem integridade transacional de dump, roles, TLS, RLS ou store.

## Regressões reproduzíveis

```bash
python -m unittest discover -s tests -p 'test_alpha_e0_recovery_preflight.py' -v
```

Os novos testes conferem:
- Rejeição de **link simbólico no diretório pai** de uma origem regular (não apenas no nome final).
- Substituição controlada do arquivo regular por symlink entre o `lstat()` e a abertura. A tentativa é recusada sem emitir informações privadas.
- Persistência do caminho normal de captura e verificação com evidências sintéticas.

## Homologação pendente

A correção qualifica somente o acesso aos arquivos de entrada do gate **offline** R06. O estado de EVE-NG E0 continua `NOT RUN`; a recuperação real entre clusters, verificação de roles/grants/RLS/TLS, RPO/RTO, R02/T14 e aceite Alpha continuam pendentes. Não executar scripts destrutivos de restore fora de cluster descartável autorizado.
