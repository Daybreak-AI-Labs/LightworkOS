<!-- Tradução mantida pela comunidade de docs/getting-started.md (commit de origem: b05c5ff) — a versão em inglês é a oficial. -->

# Primeiros passos

As seções de primeira execução e monitor foram atualizadas com esta revisão; outras seções podem estar defasadas em relação ao inglês. [English](../../getting-started.md).

## Instalação

O Lightwork é instalado a partir do código-fonte; você precisa de Python 3.11–3.12 e Git. Siga o [guia de instalação a partir do código-fonte](../../source-install.md), que traz os comandos para macOS, Linux e Windows. Ainda não há binários pré-compilados, pacotes no PyPI nem imagens de contêiner publicados. No momento não há nenhuma versão publicada; instale a partir de `main`.

Depois execute `lightwork dashboard` e abra <http://127.0.0.1:8765> para concluir a configuração do proprietário e do provedor de modelos.

## Primeira execução

No painel, abra **Start → Set up named sign-in** antes de convidar a equipe. O proprietário local escolhe um endereço de email como identificador e uma frase secreta; isso encerra o acesso anônimo de administrador. O email é uma identidade local: a caixa postal não é verificada. Mantenha os links de convite privados. Para entrar novamente neste computador, use `/auth/local-login`. Conceda permissões de espaço de trabalho e departamento em **Users**.

A configuração do primeiro proprietário aceita apenas solicitações locais diretas neste computador, antes de configurar funções ou login gerenciado. `[dashboard] local_owner_setup` é `true` por padrão; `MAVERICK_LOCAL_OWNER_SETUP=0` a desativa. As políticas existentes de login e convites continuam válidas.

O assistente e suas verificações também podem ser executados pelo terminal:

```bash
lightwork init
lightwork preflight
lightwork doctor
```

O assistente grava `~/.maverick/config.toml` e `~/.maverick/.env`. Uma nova configuração pessoal sugere US$ 2 e 30 minutos por tarefa; você pode escolher outros limites ou nenhum. Altere essa escolha em **Settings → General → Spending per task**. Sem limite por tarefa, os gastos continuam sendo registrados e cobrados pelo provedor; os limites da organização continuam válidos. Veja os [limites de tarefas](../../task-limits.md).

Se nenhum daemon do Docker em execução foi encontrado, alterações de arquivos e execução de programas ficam desativadas: o backend alternativo `local` executaria comandos diretamente neste computador, sem isolamento. Comece com esta tarefa:

```bash
lightwork start "Draft a one-page plan to reduce our customer support response time without adding headcount. State your assumptions and the facts you need from me."
```

## Veja o enxame decompor o objetivo

Execute `lightwork monitor` em outro terminal. Para a primeira tarefa, o planejamento poderia aparecer assim:

```
Goal #1 active  2m elapsed
Draft a one-page support response plan

Plan tree
  ├─        done  #2 Identify likely response-time bottlenecks
  ├─      active  #3 Draft actions that do not require hiring
  └─     pending  #4 Check assumptions and questions for the owner

Latest episode #7 (running)  $0.0431  in=18,204 out=2,910 tools=11

Recent activity
  4s ago [researcher] decision: separate volume from process delays
  3s ago [writer] draft: owner-facing plan with assumptions
  1s ago [verifier] review: mark unsupported savings estimates

Cumulative spend on this DB: $0.21
```

Para alterar arquivos ou executar programas depois, inicie Docker ou Podman, escolha o contêiner em **Permissions → Where work runs** e confirme **Allow file work**. O Lightwork verifica o contêiner e mostra outras políticas que bloqueiem a ação; `lightwork doctor` mostra a mesma limitação.

Ao terminar:

```bash
maverick status      # what's currently active or blocked
maverick skills      # what the swarm distilled from this run
maverick facts       # what it learned about you
```

## Pausar / retomar

Se o enxame precisar de algo que só você pode responder, ele pausa e coloca uma pergunta na fila:

```bash
maverick status
# shows: open questions: #3 (goal 1): Which dates are you traveling?

maverick answer 3 "May 15-29"
maverick resume
```

Os objetivos sobrevivem a reinicializações. Você pode fechar o notebook e voltar amanhã.

## Desfazendo as edições de arquivos de uma execução

Com o diário do espaço de trabalho ativado (`[workspace] journal = true`, ou
respondendo sim na etapa *Workspace journal* do assistente), cada arquivo que
os agentes sobrescrevem ou criam pelas ferramentas de arquivo é capturado
antes da mutação:

```bash
maverick journal list --goal 12     # o que foi tocado
maverick journal diff --goal 12     # estado pré-execução vs o disco agora
maverick journal revert --goal 12   # restaura cada arquivo, do mais recente ao mais antigo
```

Reverter grava uma linha de auditoria assinada `workspace_revert` e arquiva o
diário. Mutações feitas pelo shell (`rm`, `mv`, redirecionamentos) não são
registradas no diário — a trilha de auditoria registra esses comandos.

## Crie seu próprio especialista a partir de uma tarefa observada

Você não precisa descrever um trabalho com palavras — você pode demonstrá-lo.
Capture um registro ordenado de alguém realizando o trabalho (as ações que a
pessoa executou e qualquer narração do porquê) como JSONL ou texto simples com
prefixos e, em seguida, entregue o arquivo ao Lightwork:

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
maverick learn-demo demo.txt
```

Isso analisa a demonstração, induz um rascunho de especialista, mostra a você o
fluxo de trabalho derivado e aguarda sua aprovação antes de salvar. Os segredos
são removidos logo na entrada, e o rascunho herda o mesmo limite de capacidades
e a mesma varredura de persona que um pacote descrito recebe — nada é ativado
sem o seu sim. Flags úteis:

```bash
maverick learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm` espelha de forma determinística os passos observados (as ferramentas
= o que a pessoa usou); omita-o para deixar o modelo propor a partir da
transcrição.

O mesmo fluxo de fábrica de agentes é executado quando você cria um pacote de
forma conversacional:

```bash
maverick onboard
```

Após a aprovação, o `onboard` agora provisiona o pacote — ele instala as skills
do catálogo de que o fluxo de trabalho precisa e sintetiza quaisquer ferramentas
declaradas que não sejam nativas, de modo que um especialista recém-aprovado
esteja equipado para fazer seu trabalho desde a primeira execução. (Essa etapa
respeita a configuração `[self_learning]` / `provision_packs` e nunca amplia o
envelope limitado do pacote.)

## Entrada de voz (integrada, offline)

O botão de microfone do painel e a ferramenta `transcribe_audio` funcionam sem
chave de provedor: o motor Whisper local vem junto com o pacote do painel, mas
abrir o aplicativo não baixa os arquivos do modelo por padrão. Em
**Settings → Models**, na seção de ditado por voz, um administrador global
pode conferir
a origem e o tamanho do modelo configurado (cerca de 148 MB no modelo padrão)
e verificá-lo ou baixá-lo. O progresso persiste após recarregar a página;
cancelar remove o download incompleto, e falhas podem ser tentadas novamente
na mesma tela. Arquivos existentes só são marcados como verificados quando
tamanho exato e checksum conferem. Isso não comprova que o motor de voz esteja
carregado nem que o microfone funcione.

O instalador pergunta explicitamente se downloads na inicialização são
permitidos. Uma configuração salva de `[voice] auto_fetch_model = true` ou
`MAVERICK_VOICE_AUTO_FETCH=1` ainda os habilita; a política de rede vale
também para redirecionamentos. Caminhos de modelos personalizados gerenciados
e o backend de voz em nuvem escolhido mantêm sua configuração. A CLI opcional também está disponível:

```bash
maverick voice setup    # baixa o modelo verificado por checksum (~148 MB)
maverick voice status   # mostra quais backends de fala-para-texto estão disponíveis
maverick voice transcribe clip.wav   # teste rápido do pipeline
```

Prefere um motor do sistema? Um binário `whisper.cpp` no PATH
(`brew install whisper-cpp`) ou o faster-whisper entram na mesma cadeia.
Defina `[voice] stt_backend = "local"` para manter o áudio na máquina mesmo
com chaves OpenAI/Groq configuradas.

## Trocar de modelos ou provedores

Após a instalação, abra **Settings → Provider keys** ou **Settings → Models**
para mudar essas opções. A página indica os valores controlados pela
implantação; um administrador da instalação precisa alterar essa origem
antes que o novo valor entre em vigor. Consulte [`configuration.md`](../../configuration.md)
para conhecer as configurações subjacentes.

## Onde os dados ficam

| Arquivo | O que é |
|---|---|
| `~/.maverick/config.toml` | Sua configuração (implantação, modelos, segurança, orçamento) |
| `~/.maverick/.env` | Chaves de API (chmod 600) |
| `~/.maverick/world.db` | Modelo de mundo persistente: objetivos, fatos, episódios |
| `~/.maverick/skills/` | Arquivos SKILL.md destilados automaticamente de execuções bem-sucedidas |
| `~/maverick-workspace/` | Diretório de trabalho padrão do sandbox |
| `~/.maverick/learned-skills/` | Skills destiladas pelos loops de aprendizado |
| `~/.maverick/dreams/` | Insights consolidados, fila de ensaio, snapshots de aprendizado |

Lightwork armazena os arquivos acima na sua implantação. Se você ativar
provedores de IA na nuvem ou serviços conectados, o trabalho enviado a eles
pode sair dessa implantação. Revise cada provedor, conector e política de
saída antes de usá-los.

Depois de algumas execuções acumuladas, a superfície de aprendizado se resume a
quatro comandos: `maverick dream` (consolidar a experiência), `maverick hindsight`
(o aprendizado ajudou ou regrediu?), `maverick proof` (entregas, custo evitado,
ROI) e `maverick domains-lint` (auditar o catálogo de especialistas),
além de `maverick domains-audit` (postura de governança: o que cada
agente pode acessar, nega e recusa) e `maverick domains-eval --check` (casos de
referência comportamentais).
