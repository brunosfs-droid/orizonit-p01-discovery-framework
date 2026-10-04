# ADR 0033 — enriquecimento SNMP de alvo único

Data: 04/10/2026 (-03). Decisão de implementação: aceita.
Classificação: A — MVP. Qualificação operacional: CANDIDATE.
Base: `399bc5021ca81d8a9537e846068c0f49a2292b8b`.

## Contexto

O MVP exige enriquecimento essencial de dispositivos de rede antes da Community
Beta. Já existem profiles SNMP e Secret Providers, mas nenhum adapter. O scanner
TCP não demonstra disponibilidade UDP/161. Esse incremento pode ser qualificado
com agentes SNMP sintéticos locais, independentemente dos testes de LAB adiados.

## Decisão

- Adapter separado de alvo único IPv4 literal unicast. Profile ID explícito;
  seleção revalidada por protocolo, scope e contexto antes de resolver secrets.
  Dry-run default, sem dependência SNMP, sockets ou Secret Provider. Execução
  exige acknowledgement de acesso autorizado; não exige login Cancã.
- SNMPv3 somente authPriv, SHA-256 e AES-128, declarados no profile por
  `snmp_security`. SNMPv2c somente quando explicitamente escolhido por auth_type.
  Sem downgrade, comunidade padrão, SNMPv1 ou tentativa de outro profile.
  Secrets vêm das referências existentes; nenhuma senha/community na CLI.
- PySNMP 7.1.24 como dependência opcional. GET com OIDs numéricos fixos, sem SET,
  GETNEXT, GETBULK, walks, MIBs externos ou códigos fornecidos pelo usuário.
  sysObjectID é o probe; FULL acrescenta sysDescr, sysUpTime, sysName,
  sysLocation, sysServices, ifNumber e ipForwarding. Máximo oito GETs lógicos,
  retries de aplicação zero, timeout por operação e prazo global limitados.
  Descoberta/sincronização de engine SNMPv3 pode gerar mensagens adicionais da
  biblioteca: oito GETs não é uma promessa de oito datagramas.
- Cada campo conserva seu OID e estado de cobertura; falhas parciais preservam
  os valores anteriores. Timeout/ausência de resposta não prova credencial
  inválida. Erros usam códigos fixos; mensagens da biblioteca e exceções de
  providers nunca são copiadas. Valores remotos são limitados e têm secrets
  resolvidos redigidos antes da evidência.
- JSON e SHA256 em diretório privado novo, sem sobrescrita. Sem resolver,
  planner/executor automático, bundle/importer, banco, findings ou Web neste
  incremento. sysName/sysObjectID não são identificadores únicos de asset e
  não disparam correlação automática. Sem redes candidatas ou expansão de scope.

## Limites e qualificação

SNMPv2c não protege a comunidade no transporte; uso legado explicitamente
declarado. Resposta v2c prova acesso de leitura, não identidade autenticada do
dispositivo. Resposta v3 prova a troca validada pelo USM, não autorização comercial
ou unicidade do equipamento. O perfil pode possuir privilégios de escrita, mas
o adapter só emite GET. O mantenedor deve usar views/identidades somente leitura.

CI Linux/Windows e Python 3.10/3.12/3.13 exercitam agentes locais v2c e v3 com
criptografia real, limites, ausência de secrets e negações. Compatibilidade com
vendors, NAT, views e credenciais reais continua CANDIDATE. Nenhum teste manual,
conta, serviço ou alteração do LAB é requisito para este desenvolvimento.

Referências técnicas: [PySNMP GET](https://docs.lextudio.com/pysnmp/v7.1/docs/hlapi/v3arch/asyncio/manager/cmdgen/getcmd),
[API](https://docs.lextudio.com/pysnmp/v7.1/docs/api-reference),
[release fixado](https://pypi.org/project/pysnmp/7.1.24/).
