# Cancã v0.6.95 — R06: varredura de backup por descritores protegidos

## Problema corrigido

A versão v0.6.94 endureceu a abertura de arquivos individuais, mas os diretórios de store e configuração ainda eram percorridos com `Path.rglob("*")`. Em uma árvore modificada por outro processo, um componente poderia ser trocado por link simbólico durante a enumeração. A verificação posterior de arquivos pode detectar alterações, mas **não garante que a própria travessia permaneça no diretório autorizado**.

## Implementação

Em Linux/POSIX com `os.open(dir_fd=...)`, `O_DIRECTORY`, `O_NOFOLLOW` e `os.stat(dir_fd=...)`:

- A raiz é aberta pelo caminho absoluto componente a componente usando `O_NOFOLLOW`, fixando os diretórios intermediários por descritores.
- Cada entrada é enumerada através do descritor do diretório. Aferição `stat(..., follow_symlinks=False)`, abertura do arquivo/subdiretório relativa ao descritor de seu pai, e comparação de identidade pré/pós-leitura evitam seguir alterações para fora da árvore.
- Arquivos regulares são abertos somente com `O_NOFOLLOW | O_NONBLOCK`. Links simbólicos, arquivos especiais, entradas substituídas, diretórios modificados e recursos indisponíveis levam a falha segura.
- São mantidos o limite de **200.000 entradas** e um limite de **64 níveis** de subdiretórios para restringir uso de recursos.
- O SHA-256 da árvore preserva exatamente a serialização v1 anterior: `ROOT`, entradas de diretório/arquivo com caminhos relativos em ordem lexicográfica, delimitadores NUL e newline, tamanho, permissão e digest de cada arquivo.
- Os caminhos e conteúdos privados não são impressos. `capture` e `verify` seguem sem realizar restauração ou escrita nos artefatos de origem.

## Testes

```bash
python -m unittest discover -s tests -p 'test_alpha_e0_recovery_preflight.py' -v
```

Cobertura adicional:
- Árvore com subdiretórios aninhados preserva **o hash v1** gerado por uma referência independente.
- Troca de arquivo regular por symlink imediatamente antes do `open(dir_fd=...)` é recusada.
- Troca de subdiretório por symlink imediatamente antes do `open(dir_fd=...)` é recusada.
- Arquivo adicionado após a enumeração é detectado pela mudança de metadados do diretório e invalida o resultado.

## Limites e critério de aceite

Windows e plataformas sem essas primitivas preservam a varredura anterior, **sem proteção equivalente** contra alterações concorrentes. Mesmo em Linux, comparações de metadados não são um snapshot transacional, não evitam troca e restauração maliciosa de dados entre verificações nem cobrem escape por mount namespaces/bind mounts. O operador deve quiescer os produtores, usar storage isolado e artefatos imutáveis durante o preflight.

E0/EVE-NG continua com **dez NOT RUN**, R06 exige restauração real em cluster descartável, roles/grants/RLS/TLS e medição de RPO/RTO. A melhoria não promove a Alpha para GO nem autoriza restore.
