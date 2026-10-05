# ADR 0034 — planejamento e execução SNMP explícitos

Data: 04/10/2026 (-03). Decisão de implementação: aceita.
Classificação: A — MVP. Qualificação operacional: CANDIDATE.
Base: `1010a07d9a4bcb2db34a1baf2ab1777ff1484c24`.

## Contexto

O adapter SNMP v0.4b.7 já lê um alvo autorizado. Falta conectar a seleção
revisável de endpoints ao executor multi-target. O scanner TCP não prova UDP/161;
um profile armazenado ou um asset descoberto não autoriza tentativa SNMP sozinho.

## Decisão

- Planner aceita opcionalmente documento SNMP v0.4b.8 com até 25 endpoints
  explícitos: target_ip IPv4 literal, port UDP e profile_id. Cada IP deve existir
  exatamente uma vez nas seeds de discovery; duplicatas/endpoints desconhecidos
  são rejeitados antes de planejar. Não há CIDR, expansão, detecção UDP inventada,
  seleção automática de community ou profile alternativo.
- Se um manifest for fornecido, `allowed_protocols` deve incluir snmp e cada
  endpoint deve pertencer a authorized_scopes e não a exclude_scopes. Sem
  manifest, a declaração de endpoint autoriza somente aquele IPv4 /32 para SNMP;
  profile scope continua um gate separado. A política integra o binding do plano.
- Metadados de endpoint distinguem `operator_declared` de protocolo observado.
  Os selectors usam contexto derivado da seed/manifest e serviço declarado snmp;
  Unknown, realm declarado e conflitos continuam gates. Campos relevantes de
  contexto e configuração completa do profile (incluindo referências, não seus
  valores) são ligados ao plano por SHA256 canônico. As referências não são
  copiadas. Política v3 é revalidada pelo adapter antes de resolver secrets.
- Executor v0.4b.8 entende planos novos, mas SNMP fica desativado sem
  `--enable-snmp`. CLI de execução preserva acknowledgement de acesso autorizado
  e SHA256 do plano revisado. API/portable têm enable_snmp=false por default.
  Duplicatas e limite de 25 endpoints são rechecados antes de qualquer dispatch.
  Revalidação de endpoint, contexto, snapshots e bindings precede providers e
  se repete no dispatch. Um plano antigo sem os campos novos nunca executa SNMP.
- Dispatch usa o adapter v0.4b.7 qualificado, sem alterar seus GETs, credenciais,
  prazo ou contrato. AUTH-only conserva um probe; FULL conserva cobertura por
  campo e falhas parciais. Target JSON/SHA256 e job mantêm o envelope do executor,
  com contrato SNMP explícito dentro de enrichment.
- Após uma leitura não confirmada, o job suspende os demais endpoints SNMP que
  compartilham a identidade de referências da credencial. Esse freio não declara
  senha inválida e não consome authentication failure budget. Não há retries ou
  fallback; profiles independentes seguem normalmente. Sucesso do probe com
  FULL parcial não é falha de credencial.
- Execução habilitada com ações SNMP exige diretório de saída privado novo antes
  de qualquer dispatch; target SNMP/job usam arquivos exclusivos 0600. Planos
  SNMP também usam diretório novo 0700/arquivos 0600. Sem sobrescrita. Windows
  depende de ACL privada no parent, sem nova promessa de qualificação NTFS.
- Plano/job sem SNMP continuam na rota anterior. Default do portable não muda;
  nenhum scheduler, conta, SQL/store, finding, relatório ou Web é alterado.

## Limites

SHA256 detecta drift, não assinatura/autoria. IDs/contexto revistos não provam
verdade do inventário nem autorização externa; acknowledgement permanece humano.
Trocar valor dentro do mesmo Secret Provider reference não altera seu binding;
na tentativa seguinte o provider é consultado novamente. Hints não promovem
evidência de realm AD. SNMPv2c não protege a comunidade no transporte.

Integração SNMP no resolver/bundle/ingestão e controles managed do portable terá
incremento próprio. Este passo qualifica planejamento e execução CLI, não a
cadeia SNMP end-to-end ou vendors reais. CI loopback Linux/Windows e Python
3.10/3.12/3.13 usa somente fixtures; nenhum teste de LAB é solicitado agora.
