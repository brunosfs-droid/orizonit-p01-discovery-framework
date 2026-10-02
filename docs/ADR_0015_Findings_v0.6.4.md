# ADR 0015 — Findings imutáveis derivados de evidência inventariada

Data: 02/10/2026. Decisão anterior à implementação v0.6.4 CANDIDATE.

## Problema

O Analyzer v0.2 lê collectors locais; bundles atuais transportam enrichment
WinRM/SSH, não esses collectors. Reutilizar todos os handlers nesses JSONs daria
uma impressão incorreta de cobertura. Também é necessário conservar regra,
origem e identidade mesmo quando outra coleta não apresenta o mesmo finding.

## Decisão

Criar um adaptador offline explícito para bundles existentes, sem mudar o formato
de transporte ou o Analyzer legado. Catálogo v0.6.4 contém apenas WIN-FW-001 e
WIN-AD-001: perfis Windows Firewall e secure channel WinRM. Nenhuma alegação de
cobertura das outras 17 regras do Analyzer. SSH é registrado como not_supported.
Não coletar dados, resolver secrets ou executar comandos dos artefatos.

Cada fonte credentialed recebe uma avaliação por regra: finding, no_finding,
insufficient_evidence, not_applicable ou not_supported. Exigir autenticação
successful, collection_status collected/collected_with_section_failures e seção
exatamente uma vez com success=true/status_code=0. Booleanos devem ser booleanos
JSON. Firewall exige os três perfis conhecidos distintos; secure channel exige
identity comprovada e membro de domínio não DC, checked=true e healthy booleano.
Ausência, formato inválido, falha ou seções duplicadas são evidência insuficiente.
no_finding significa somente ausência da condição na seção avaliada.

Preparar fonte antes de conectar: validar import com o índice, repetir projeção
de assets e ler cópia privada do raw bundle vinculada ao SHA256 do import.
Somente artefatos credentialed inventariados; 16 MiB por JSON, 64 MiB somados,
até 1.000 fontes/2.000 avaliações. Store permanece somente leitura.
Projeção carrega hashes do import e da projeção de assets, catálogo completo e
SHA256 dos bytes do catálogo e do engine. Sem relógio variável nas regras atuais.
Referências de evidência são caminhos JSON fixos dentro da fonte inventariada;
não aceitar caminhos de arquivos declarados dentro do payload.

Migração 0004 adiciona análises, avaliações e ocorrências de findings. Análise é
uma versão imutável por bundle/policy_version; hash da projeção define analysis_id
e IDs de ocorrência. Replay idêntico não escreve. Drift da mesma versão exige
review/conflict, sem overwrite; nova política exige versão nova e migração/contrato.
Import e assets precisam ter sido persistidos explicitamente antes. Comparar seus
fingerprints no banco antes de gravar qualquer avaliação. Transação atômica e lock
por bundle serializam replay concorrente; não alterar lifecycle ou associações.

Ligação de fonte a exatamente uma observação conserva seu ordinal; mais de uma
ou nenhuma fica explicitamente ambiguous/unresolved, sem escolher hostname/IP.
Consulta recupera o CAS e a decisão do registro existente: um CAS provisório ou
em revisão não vira identidade confirmada por ter um finding. Ocorrências novas
começam Open; não há fechamento automático, merge de ocorrências entre runs,
deduplicação entre assessments, triagem manual, endpoint remoto ou UI neste passo.

## Verificação e limites

0001–0003 permanecem byte-idênticas. Índice, lifecycle e assets aceitam prefixos
conhecidos; findings exigem 4. Upgrade não cria análises por inferência.
Role de análise recebe SELECT nas dependências e SELECT/INSERT nas três tabelas,
sem UPDATE/DELETE/DDL. O CLI é a fronteira de proveniência; API interna e acesso
SQL continuam confiáveis, sem alegar resistência a DBA ou engine adulterado.
Guardar apenas evidência extraída pequena e referências, sem stdout/stderr bruto.

Testar fonte íntegra/read-only, evidência faltante/parcial/malformada, replay,
drift, rollback, concorrência, identidade ambígua, upgrade, paginação e role em
PostgreSQL 16/17 real. Qualificação LAB de roles/TLS/backup/restore é independente.
