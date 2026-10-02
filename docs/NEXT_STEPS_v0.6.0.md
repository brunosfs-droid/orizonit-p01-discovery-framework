# P01 — Próximos passos após scheduler R1 e fundação v0.6.0

## Preciso testar alguma coisa agora?

**Nenhum teste seu bloqueia o desenvolvimento da fundação PostgreSQL.** O R1
curto do scheduler já foi aprovado em Windows e Rocky. Não é preciso repetir
esse R1 nem reinstalar o serviço que o helper removeu ao terminar.

Existe um teste complementar pendente: **soak estendido do scheduler**. Pode ser
executado depois, nas VMs do LAB, enquanto a Product Alpha avança com dados
sintéticos e CI. Não é validação de coleta live nem de PostgreSQL.

## Soak estendido, quando houver disponibilidade

Atualize o checkout para `main` (`git pull --ff-only`) e registre `git rev-parse
HEAD` junto da execução. Use a mesma conta administrativa e os mesmos pré-requisitos
que deram PASS no R1 curto. Cada execução cria fixture nova e remove apenas seu
próprio serviço; preserve a pasta indicada no resultado. Não remova a evidência
do R1 anterior nem intenções interrompidas sem revisão.

Windows: PowerShell administrativo, **na raiz do checkout**, com Python/pywin32
já usados no R1 (se usa venv, ative-a antes):

```powershell
python tests/scheduled_agent_soak.py --lab-root C:\Canca\scheduled-lab --node-id P01-MGMT01 --ticks 10
$LASTEXITCODE
```

Rocky: shell administrativo, **na raiz do checkout**, usando o Python 3.12 já
validado no R1 e mantendo SELinux Enforcing:

```sh
/usr/bin/python3 tests/scheduled_agent_soak.py --lab-root /var/lib/canca/scheduled-lab --node-id P01-LNX-RKY01 --ticks 10
echo $?
```

O helper usa somente autorizações negadas e intervalos reais de 60s. O primeiro
ciclo de 10 ticks leva pelo menos **9 minutos por host**; não encurte o intervalo.
Depois verifica uma interrupção durante espera e um restart sem replay.

Aceitação: `SCHEDULED AGENT SOAK PASS`, exit 0, 3 starts, 11 invocações canônicas,
3 sessões de scheduler, recarga de policy, orçamento respeitado, intenção running
preservada e restart em revisão com 0 novas invocações. Envie o resultado completo,
HEAD e os arquivos indicados pelo helper para fechar esse gate. Um print de PASS
isolado não comprova soak prolongado nem coleta live.

## PostgreSQL: ainda não exige alteração sua

A v0.6.0 entrega migração e indexação explícita de imports já validados, com CI
PostgreSQL 16/17. Ainda é **CANDIDATE** para seu LAB. Não instale PostgreSQL nem
altere o store existente por causa deste guia. A qualificação do servidor terá
um roteiro próprio para base isolada, contas, TLS e backup/restore.

O próximo desenvolvimento independente é definir a integração ingestão/índice e
sua reconciliação após interrupção, antes de acrescentar lifecycle, assets, API e UI.

[Status v0.6.0](STATUS_PERSISTENCE_v0.6.0.md) ·
[R1 scheduler já aprovado](validation/SCHEDULER_P01LAB_R1_v0.5f.3.md)
