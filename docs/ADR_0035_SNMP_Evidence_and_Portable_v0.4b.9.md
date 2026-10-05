# ADR 0035 — evidência SNMP, replay e portable gerenciado

Data: 05/10/2026 (-03). Decisão de implementação: aceita.
Classificação: A — MVP. Qualificação operacional: CANDIDATE.
Base: `e9250e12d53bb2e941c9e6bb888561166f69b94e`.

## Contexto

O adapter v0.4b.7 e o planejamento/executor v0.4b.8 estão qualificados com
agentes sintéticos. Seus resultados ainda precisam percorrer o resolver,
bundle e replay offline, e o portable precisa oferecer o mesmo fluxo explícito.
`sysObjectID` identifica um produto/modelo, não um dispositivo único; um nome
informado pelo operador não é identidade coletada nem prova de associação AD.

## Decisão

- Uma leitura pura, limitada e sem dependências SNMP interpreta os envelopes
  standalone v0.4b.7 e target do executor v0.4b.8. Valida os oito campos/OIDs,
  tipos, limites, estados, contagens e cobertura antes de consumir a evidência.
  Não importa adapter, provider ou biblioteca de rede. Documento reconhecido
  como SNMP inválido é rejeitado, sem fallback para identidade genérica.
- Resolver v0.4c.1 mantém valores coletados como claims `snmp.*` observados,
  vinculados ao SHA256 da fonte e ao OID. Mantém cobertura e falhas por fonte.
  FULL com acesso confirmado pode produzir inventário com campos parciais.
  AUTH-only, dry-run e falhas permanecem diagnósticos, sem criar/promover assets.
- Somente `sysName` remoto utilizável participa da correlação por namespace,
  sempre com evidência independente de endereço/MAC. IP, `sysObjectID`, nome do
  plano e tipo/vendor/realm declarados não são identificadores fortes. Observação
  SNMP sem correlação usa seu próprio anchor determinístico, evitando colisão
  por nomes de equipamentos iguais. Fontes de bytes idênticos são deduplicadas.
  Nome SNMP não promove realm AD via suffix do manifest. Uptime variável conserva
  proveniência sem gerar conflito de configuração/identidade.
- Bundle v0.5a.1 conserva formato v0.5a, roles, bytes e SHA256 existentes;
  valida contratos SNMP na criação e na leitura. Importer v0.5b.1 refaz a
  correlação sem rede e compara também cobertura/claims SNMP com o resolver
  embarcado. Fluxos legados mantêm sua projeção semântica anterior. Integridade
  por hash não é assinatura ou autenticação da origem.
- Portable v0.5e.7 aceita `--snmp-requests` no planejamento; registra a referência
  e SHA256 e bloqueia drift antes das etapas de acesso. Prévia, AUTH e FULL
  exigem `--enable-snmp` explícito para planos SNMP. Cada etapa vincula a opção
  à evidência anterior, sem ativação automática pelo scheduler. Uma etapa já
  concluída retorna seu resultado sem nova rede. Sem SNMP, defaults anteriores.
- Planejamento e cada tentativa SNMP usam diretórios privados novos e arquivos
  exclusivos. AUTH parcial/falho bloqueia FULL. FULL SNMP com acesso confirmado
  e cobertura parcial conserva os campos disponíveis e contabiliza a cobertura
  separadamente; não inventa sucesso dos campos ausentes. Falhas de SSH/WinRM
  conservam os gates anteriores. Repetição de tentativa falha continua explícita.
- O portable continua sem login Cancã. Credenciais de coleta permanecem no
  provider existente, fora de estado/evidência. Web login e Node mTLS continuam
  fronteiras separadas. Não muda scheduler, contas, SQL/store, findings ou Web.

## Validação e limites

Qualificar contratos puros, correlação negativa, adulteração, resume sem rede e
cadeia portable → FULL → resolver → bundle → replay com UDP loopback v2c/v3
authPriv em Linux/Windows/Python 3.10, 3.12 e 3.13. Manter regressões existentes.
O adapter v0.4b.7 permanece intacto. Vendors reais/LAB continuam pendentes.
Windows depende de ACL privada no parent; este incremento não qualifica NTFS.
Troca do valor no mesmo provider reference não altera o binding de configuração.
