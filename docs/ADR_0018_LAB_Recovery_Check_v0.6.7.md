# ADR 0018 — verificação de recuperação no LAB

Data: 02/10/2026. A v0.6.6 já qualifica dump/restore real no CI; o R1 básico Rocky foi demonstrado em capturas. Falta comparar banco/store antes/depois na instalação do operador.

Decisão: adicionar um helper de validação R1, separado das CLIs de produto, com capture/verify somente leitura no banco e store. Ele exige o nome explícito da base e a fixture isolada P01-PG-LAB-R1 com dois imports completamente projetados. Não cria base, migra, apaga, corrige dados, chama Docker ou executa backup/restore. O operador executa esses comandos em destino novo conforme roteiro separado.

A captura lê as 14 tabelas num snapshot REPEATABLE READ READ ONLY, ordena representações JSON das linhas e registra somente contagens/hashes. Revalida bundles/receipts e projeções de import/assets/findings com o código original, comparando-as às fingerprints persistidas. Inventaria todos os arquivos relativos do store com SHA256 antes/depois. Verify exige igualdade integral com a captura de origem e mesma major PostgreSQL; o nome da base e o caminho absoluto do store não entram na igualdade porque mudam na restauração.

Bounds R1: 200 linhas por tabela, 1 MiB por linha, 8 MiB de representações por tabela; até 100 arquivos/16 MiB por arquivo/64 MiB total do store. Excesso, symlinks, dados fora da fixture, hash inválido, código de projeção divergente ou source/DB mismatch rejeitam o resultado inteiro. Sem resumo parcial. Não é ferramenta para bancos ou assessments grandes.

Saída de capture: novo diretório privado com snapshot JSON e sidecar SHA256, sem senha, corpo da evidência ou linhas do banco. Verify só lê; nenhum output é sobrescrito. SHA256 identifica bytes mas não autentica o operador nem impede DBA/atacante de forjar manifesto e sidecar. Capture/verify dependem de escritores parados durante todo o par dump/cópia; não são snapshot distribuído ou proteção contra concorrência adversarial.

CI: integrar o helper no smoke de recuperação existente em PostgreSQL 16/17 e testar recusa de base errada, origem alterada, fixture fora do escopo, limites, referência corrompida e erro redigido. O helper permanece candidato até o operador executar o novo roteiro no Rocky.

Proveniência do código no Rocky: o engine hash mostrado é o hash CRLF do código original v0.6.5. O roteiro adiciona apenas o helper novo ao deployment original, preservando os módulos que produziram as projeções; não normaliza EOL, substitui engine ou reescreve fingerprints persistidas. CI LF e LAB CRLF são qualificados dentro da sua própria cadeia de bytes.
