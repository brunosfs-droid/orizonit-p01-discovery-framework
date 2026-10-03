# Seleção de assessments na Web v0.6.16

Status: CANDIDATE. Desenvolvimento e CI independentes dos testes manuais adiados
pelo mantenedor em 03/10/2026 (-03). Nenhuma ação no LAB solicitada hoje.

## Uso

Após entrar, **Assessments permitidos** mostra os IDs autorizados para sua conta.
Escolha um ID e clique em **Consultar**. A seleção preenche o formulário e limpa
o relatório anterior; não inicia consulta, coleta ou exportação automaticamente.
**Atualizar lista** repete a leitura das permissões da sessão atual.

A lista contém permissões cadastradas, sem consultar a existência dos relatórios.
Um ID permitido ainda pode retornar **Assessment não encontrado** ao consultar.
Ela não mostra estado, cliente, assets ou findings. Sem permissões, a mensagem
explica que a conta não possui assessments permitidos. O campo de ID permanece
disponível; qualquer consulta continua sujeita à autorização exata no servidor.

Se a lista estiver indisponível, atualize ou informe um ID autorizado. Uma falha
de atualização não invalida o relatório já carregado. Editar o ID manualmente
mantém o relatório exibido e o escopo capturado de seus downloads até a próxima
consulta, conforme o contrato anterior. Selecionar na lista limpa o relatório.

Sessão expirada, Sair e restauração da página limpam a lista e os resultados.
Respostas atrasadas de uma sessão anterior são descartadas. A lista e o token
permanecem apenas na memória da página. Atualizar a lista não renova a sessão.

## Contrato do servidor

Somente o listener Web v0.6.16 oferece `GET /api/v1/operator/assessments`. O
listener API v0.6.11 mantém suas rotas anteriores. O acesso usa o mesmo Bearer,
as regras de origem/Host e a política privada de contas carregada no startup.
Query e body são rejeitados. Não há parâmetros para escolher outro operador.

Resposta HTTP 200:

```json
{
  "status": "allowed",
  "version": "0.6.16",
  "source": "local_operator_policy",
  "assessment_existence_checked": false,
  "assessment_ids": ["LAB-001", "LAB-MISSING"]
}
```

IDs são únicos, ordenados por ASCII e sensíveis a maiúsculas/minúsculas. São no
máximo 128 IDs de 128 caracteres; resposta limitada a 32 KiB. O cliente verifica
tipo, semântica, ordem, unicidade e limites antes de criar opções como texto.
Nenhuma conta, hash de senha, token ou permissão de outro operador é exposta.
Sem sessão válida: 401. Query/body inválidos: 400. Origem negada: 403. Método/rota
não suportados: 404. Erro inesperado/limite: 503 com código fixo, sem detalhes.

`LocalAuth.assessment_grants(token)` retorna uma tupla imutável sob o lock da
sessão. A verificação de sessão é repetida imediatamente antes da resposta.
Como nas demais requisições, revogação posterior à última checagem não apaga bytes
já enviados. Alterações da política exigem restart controlado, que invalida todas
as sessões. O formato da política e o contrato de autenticação v0.6.11 permanecem.

Não abre PostgreSQL, acessa store, cria arquivos, migra schema ou altera grants.
A lista é independente do slot de exportação; operações no mesmo cliente são
serializadas. Controles e limites dos downloads técnico/executivo permanecem.
Collector portable continua sem login Cancã; AD, criação de assessments,
inventário, importação e mapper seguem decisões/etapas separadas.

## Qualificação

- Auth/HTTP real: isolamento entre contas, vazio/máximo, limites, origem/query/body,
  expiração/revogação, erros fixos e zero chamadas SQL na listagem.
- Eventos: seleção sem requisição automática, limpeza do relatório, texto seguro,
  atualização/fallback e respostas tardias após logout/expiração/nova sessão.
- PostgreSQL 16/17: permissão de ID inexistente, consultas por reader, negações
  antes de SQL e preservação das 14 tabelas/arquivos da fixture sintética.
- Chromium desktop/mobile: seletor, ID inexistente, separação entre contas, vazio,
  os dois downloads e integridade, sem requests externos/storage/cookies.

LAB operacional e produção continuam gates próprios. Guias v0.6.11–v0.6.15 são
históricos; usar seus pins, sem misturar fontes HEAD com pacotes qualificados.
O launcher manual v0.6.13 rejeita v0.6.16 antes de solicitar senha ou abrir banco.

[ADR 0028](ADR_0028_Operator_Assessment_Selection_v0.6.16.md) ·
[Registro CI](validation/OPERATOR_ASSESSMENT_SELECTION_CI_v0.6.16.md).
