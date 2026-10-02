# Cancã v0.6.3 — Identidade persistente de assets

Data: 02/10/2026 (-03). **LAB VALIDATED — R1 básico sintético; escopo restante CANDIDATE**, Product Alpha, refs #63.

Registro central com ID `cas-`, escopo assessment, observações por bundle/ordinal,
sinais qualificados e referências aos artefatos verificados. Projeção explícita de
um import indexado, fonte verificada antes de conectar e replay privado do resolver
offline. `source_asset_id` é referência local e pode se repetir; nunca é chave global.

Associação exige candidato único e dois sinais credentialed de categorias diferentes,
incluindo um forte; divergência forte ou ambiguidade bloqueia. Casos insuficientes
mantêm registro provisório/observação de revisão com candidatos. Não há merge/relink
ou decisão silenciosa por IP, hostname ou score. Nenhuma correlação entre assessments.

Migração 0003 explícita, sem backfill inferido; preserva 0001/0002 e lifecycle.
API/bridge permanece v0.6.1, lifecycle v0.6.2, runtime v0.5e.6, scheduler v0.5f.3,
resolver v0.4c.0. PostgreSQL foundation/registro passa para v0.6.3.

Testes de fonte locais e PostgreSQL 16/17 real incluem proveniência, fonte adulterada,
resolver embutido sem autoridade, qualificação credentialed, replay, concorrência,
IP/serial reutilizados, chaves SSH com case distinto, IDs locais duplicados, escopo,
upgrade com dados, rollback, limites de candidatos e leitura/role sem relink/delete.
Resultados do commit exato constam no PR de integração e relatório da entrega.

Limites: identidade física não garantida, clones, registros provisórios sem resolução
manual nesta versão, no máximo 100 candidatos/100 observações anteriores para decisão
automática. Sem RBAC/UI/findings ou qualificação P01LAB PostgreSQL TLS/roles/restore.

[ADR 0014](ADR_0014_Persistent_Assets_v0.6.3.md) ·
[Guia](ASSET_REGISTRY_v0.6.3.md)

## Atualização de qualificação em 02/10/2026

O R1 básico em PostgreSQL 16.15 no Rocky passou: migração/replay, dois imports,
1 CAS/2 observações, 4 avaliações/2 findings históricos Open e leitura por reader
com UPDATE negado. [Aceite e 18 capturas](validation/POSTGRESQL_P01LAB_R1_v0.6.5.md).
A observação nova substitui a pendência inicial de instalação e fixture. Não
qualifica API com índice, transições lifecycle, cursor/fence completo, TLS remoto,
roles de escrita separados ou restore operacional. Próximo gate: [recuperação R1](LAB_POSTGRESQL_RECOVERY_R1_v0.6.7.md).
