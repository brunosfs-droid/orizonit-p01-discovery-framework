# ADR 0014 — Identidade persistente de assets por assessment

Data: 02/10/2026 (-03). Aceito antes da implementação v0.6.3 CANDIDATE.
Escopo A/MVP, refs #63; segue ADRs 0011–0013.

## Problema

O resolver v0.4c.0 correlaciona evidências offline dentro de um bundle. Seu `ast-`
deriva do seed hostname/FQDN/MAC/IP e pode se repetir entre observações distintas;
não é chave de identidade global. O índice central precisa manter ID, associação
entre imports e proveniência sem apagar sinais conflitantes.

## Decisão

Migração 0003 cria registro de assets, projeções por import, observações por ordinal
e sinais normalizados. ID central `cas-<UUID hex>` é gerado na primeira persistência
e permanece estável no replay e nas associações aceitas. `source_asset_id` é apenas
referência ao resolver; ordinal preserva observações mesmo com IDs locais duplicados.
Escopo é `assessment_id`: não correlacionar automaticamente assessments/clientes,
sem um modelo de tenancy/environment e aprovação de continuidade entre assessments.

Operação explícita `project-import` exige um import previamente indexado e fonte
verificada antes da conexão. Revalidar recibo/raw bundle, fixar uma cópia privada
do bundle pelo SHA256, extrair apenas JSONs inventariados para área temporária e
reexecutar `resolve` offline. Não confiar no JSON do resolver embutido ou processed
para decidir identidade. Não modificar o store, recibo ou arquivos processed.
JSONs limitados a 16 MiB cada/64 MiB total; até 10.000 assets e 64 sinais por asset.
Sem execução de payload, coleta, autenticação, rede ou alteração do runtime.

Sinais fortes aceitos vêm apenas de fontes credentialed com `authentication.success
= true` e `collection_status = collected`: serial não genérico e SSH SHA256 válido.
FQDN credentialed é corroborador; IP/hostname/MAC de rede são contexto/propostas.
Serial é normalizado em minúsculas; fingerprint SSH mantém base64 case-sensitive
do JSON original, pois o resolver legado transforma seus identificadores em lowercase.
Proveniência liga cada sinal aos caminhos relativos/hashes dos artefatos verificados.

Associação automática exige exatamente um candidato elegível, coincidência de pelo
menos um sinal forte e de duas categorias credentialed independentes (serial+FQDN,
SSH+FQDN ou serial+SSH). Categorias fortes divergentes bloqueiam associação. Sinais
do candidato devem ter coexistido em uma observação anterior aceita, sem combinar
corroboradores de imports diferentes. Conflito/ambiguidade local, ID local duplicado,
múltiplos candidatos ou sinais insuficientes não autorizam associação automática.
Sem candidato, criar ID novo; sem prova suficiente, o registro permanece provisório.
Revisão cria observação/ID provisório separado e conserva até 100 candidatos com
flag de truncamento. Mais de 100 observações aceitas num candidato também exige
revisão conservadora, evitando pesquisa de histórico ilimitada para decidir.
Não incorpora sinais de revisão ao conjunto aceito de candidatos.
Não fundir assets existentes, escolher por score nem relinkar observações antigas.

Transação e lock por assessment serializam projeções de diferentes bundles; um
fingerprint de projeção por bundle assegura replay idempotente e detecta drift.
Índice do import, IDs e hashes devem corresponder à fonte. Estado/decisões e sinais
ficam atômicos. Falha preserva índice anterior; sem retry ou migração automática.
Consultas paginadas/read-only preservam a origem e não promovem registros.

## Compatibilidade e limites

0001/0002 permanecem byte-idênticos. Índice aceita prefixos conhecidos 1/2/3,
lifecycle aceita 2/3; assets exigem 3. DDL explícito; nenhum backfill de associação
é inferido. Roles de assets são separadas do indexador e do operador de lifecycle.
IDs/sinais são metadados potencialmente confidenciais; bytes de evidência continuam
no store. Não alegar identidade física garantida: clones podem copiar serial/FQDN/
chaves. Nenhuma correlação inter-assessment, reconciliação manual de IDs, interface
remota, findings, CMDB/IPAM ou UI neste incremento. Isso fica explícito nos contratos.

Validar PostgreSQL 16/17 real: upgrade com dados, replay, source/index drift,
rollback, concorrência entre bundles, DHCP/IP reutilizado, serial compartilhado,
contradição forte, múltiplos candidatos, escopo entre assessments, fingerprint com
case distinto, ID local duplicado e leitura sem mutações. LAB PostgreSQL ainda é gate
independente de roles/TLS/backup/restore.
