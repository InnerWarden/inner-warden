# InnerWarden Community

> Documento guia. Descreve o que este produto **é hoje**, verificado no código, não o que se pretende que ele seja.
> Datado de 2026-08-06, workspace `1.1.0`, repo `github.com/InnerWarden/inner-warden` (público, Apache-2.0).
>
> **Para o operador:** corrige o que estiver errado ou mal formulado. Depois disto ser aprovado, o código é que se ajusta ao documento, e não o contrário.

---

## 1. O que é, em uma frase

Um **guardrail para agentes de IA**: liga-se ao agente que a pessoa já usa, seja OpenClaw, Claude Code, Cursor, Codex ou Gemini, e inspeciona o que esse agente quer fazer antes de ser feito.

Não é uma ferramenta para programadores. É para **quem quer que corra um agente de IA** na sua máquina. O programador é um caso de uso, não o público.

## 2. Um produto, dois níveis

**InnerWarden é um produto só.** O Community é o nível base; o Active Defence é o mesmo produto com mais camada por baixo. Não são dois produtos concorrentes nem duas instalações rivais.

| | Community | com Active Defence |
|---|---|---|
| Protege | o agente | o agente **e** a máquina onde ele corre |
| Vê | o que o agente propõe: comandos, chamadas MCP, ficheiros | tudo isso, mais kernel, syscalls, execs e rede |
| Comando | `innerwarden` | `innerwarden` (o mesmo) |

Por isso o comando é **o mesmo nome nos dois níveis**: `innerwarden`. Não há dois CLIs. Quem instala o Active Defence não troca de ferramenta, ganha comandos.

### Como isso funciona por dentro

O binário `innerwarden` (este repo) é a **porta de entrada única**. Trata os verbos da camada do utilizador; qualquer outro verbo é reencaminhado para o `innerwarden-ctl` do Active Defence, se estiver instalado (`upsell_io.rs:37`). Se não estiver, e for um verbo de host conhecido, explica o que o Active Defence acrescenta.

O `innerwarden-ctl` **não é para ser chamado à mão pelo utilizador**. É o motor por trás do mesmo comando.

### A ordem de instalação, que é a regra que governa tudo

O caminho normal do cliente é este, e só este:

1. Instala o **Community**. Fica protegido na camada do agente.
2. Paga.
3. Instala o **Active Defence por cima** da instalação que já tem.

O passo 3 é **aditivo**. Nunca substitui, nunca remove, nunca enfraquece o que o passo 1 deixou a funcionar.

> **Invariante, e é testável:** depois de instalar o Active Defence, **tudo o que funcionava antes continua a funcionar exactamente igual**, e há verbos novos. Nenhum comando desaparece. Nenhum default fica mais fraco. Nenhuma proteção é trocada por uma mais frágil.

Isto não é um princípio decorativo: é o critério de aceitação do instalador do Active Defence. Hoje **falha nos cinco pontos** listados em «Pontos por esclarecer», e todos eles são a mesma falha vista de ângulos diferentes, o nível pago a substituir em vez de acrescentar:

| o que o passo 3 estraga hoje | ponto |
|---|---|
| apaga os verbos gratuitos da linha de comandos | 1 |
| torna inalcançáveis os verbos partilhados | 2 |
| baixa o default do proxy MCP de `guard` para `advisory` | 3 |
| troca o hook local por um script com mais dependências e que bloqueia tudo se falhar | 4 |
| disputa a porta 8787 com quem já lá estava | 5 |

O instalador do Active Defence hoje **nem sequer verifica se o Community está instalado** (`web-install.sh` só preserva as configs dele próprio). Passa por cima às cegas.

## 3. A camada onde atua

O Community atua **na camada do utilizador**. Vê o que o agente propõe fazer e age aí.

**Não vê** drivers, kernel, syscalls, nem nada que não passe pelo agente. Isso é o que o Active Defence acrescenta.

## 4. O que NÃO é

- Não é um EDR, nem um antivírus, nem um sensor de host.
- Não observa a máquina. Só vê o que um agente lhe entrega.
- Não vê o que acontece abaixo do agente: nada de kernel, drivers ou syscalls.
- Não protege contra um atacante com root. Protege contra um agente de IA que se engana ou é manipulado.
- Não corre como serviço. Não tem base de dados. Não toca no kernel.

## 5. Forma física

Um único binário chamado `innerwarden`. Cinco crates no workspace, mas só `cli` produz binário.

| Crate | Papel |
|---|---|
| `cli` | O binário `innerwarden`. Todos os comandos. Deliberadamente não depende de sensor/agent, para continuar portável a Windows. |
| `agent-guard` | O motor. Análise de comandos shell, deteção de prompt injection, fuga de credenciais, regras ATR, proxy MCP. |
| `graph` | Modelo puro do grafo de decisões. Zero I/O de propósito, quem persiste é o `cli`. |
| `notify` | Resolução de config e construção de payloads para Telegram/Slack/Discord/webhook. Não traz transporte HTTP. |
| `dashboard-kit` | Contrato versionado do dashboard, validadores fail-closed, e o bundle React embutido. |

**Plataformas:** o binário compila e é publicado para Linux, macOS e Windows, em x86_64 e arm64 (seis pacotes npm a partir do mesmo código). Mas **não são equivalentes**: Linux e macOS são de primeira linha, Windows é experimental. O `contain` recusa-se a correr fora de Linux e macOS, porque depende de bubblewrap ou do sandbox do macOS.

**Instalação:** `curl -fsSL https://innerwarden.com/free | sh`, npm, `cargo install`, ou pacotes deb/rpm.

**Estado local:** `~/.config/innerwarden/` (grafo de decisões em `graph.json`, configurável por `IW_GRAPH_FILE`).

## 6. O que efetivamente bloqueia, e o que é só opinião

Esta é a distinção mais importante do produto e onde a comunicação costuma escorregar.

### Bloqueia de facto

| Comando | Mecanismo |
|---|---|
| `innerwarden hook` | Adaptador PreToolUse do Claude Code. Lê a tool call no stdin e devolve exit 2 para **bloquear**. É o agente que respeita o exit code. |
| `innerwarden proxy` | Man-in-the-middle stdio à frente de um servidor MCP. O default da linha de comando é `guard`, ou seja, bloqueante. |
| `innerwarden contain` | Isolamento com bubblewrap (Linux) ou o sandbox do macOS, com o hook vivo lá dentro. **Não existe em Windows**: o comando falha com erro explícito. |

Desde 2026-08-05 o `hook` tem ainda uma **camada comportamental**: conta as chamadas por sessão e sobe um `allow` para `review` quando o agente passa dos limites partilhados (30 por minuto). Nunca inventa um `deny` sozinho, porque descreve a sessão e não aquele comando. Ver ponto 7.

### Só aconselha

| Comando | Comportamento |
|---|---|
| `innerwarden check` | Analisa um comando e devolve veredicto. Exit 1 em `deny`. **Não impede nada**, quem chama é que tem de olhar para o exit code. |
| `innerwarden serve` | HTTP em loopback (`127.0.0.1:8787`), rota `POST /api/agent/check-command`. Devolve veredicto, não bloqueia. |

**Consequência honesta:** o produto só é enforcement quando o agente coopera. Um agente que deixe de chamar o hook não é travado por ele. É por isso que existe o Active Defence.

## 7. Que agentes protege

**Intenção do produto:** o utilizador não deve ter de saber qual agente tem. O InnerWarden deteta o que está instalado, liga-se, e protege, seja OpenClaw, Claude Code ou outro.

**Estado atual, verificado no código e ponta a ponta a 2026-08-05:**

| Agente | Como é protegido | Automático? |
|---|---|---|
| Claude Code | hook PreToolUse | sim, `innerwarden install` |
| **OpenClaw** | proxy MCP, via `.openclaw/openclaw.json` | **sim**, `innerwarden agents connect openclaw` |
| Cursor | proxy MCP, via `.cursor/mcp.json` | sim, `innerwarden agents connect cursor` |
| Codex CLI | proxy MCP, via `.codex/config.toml` | sim, `innerwarden agents connect codex` |
| Gemini CLI | proxy MCP, via `.gemini/settings.json` | sim, `innerwarden agents connect gemini` |
| Goose | nada ainda | não, guarda os servidores em YAML |
| Aider, Hermes | nada ainda | não, sem superfície MCP revista |

O `agents connect` **reescreve a configuração MCP do agente** para passar pelo proxy, de forma reversível e idempotente. Não é conselho, é o produto a ligar-se sozinho.

### O OpenClaw, que era a lacuna deste documento

Até 2026-08-05 o OpenClaw não tinha caminho nenhum, e era o primeiro nome que a frase de abertura dava. A razão não era o formato JSON5, como estava escrito: era o `mcp_wire` localizar a tabela de servidores só por **chave de topo**, e o OpenClaw guardar a dele em **`mcp.servers` aninhado**.

O localizador passou a ser um caminho em vez de uma chave. Provado ponta a ponta com uma config real:

```
antes:   command: npx                args: -y fs-server
depois:  command: <innerwarden>      args: proxy --mode guard -- npx -y fs-server
         auth preservado: sim        mcp.allowed preservado: sim
disconnect: command e args restaurados exatamente
```

**A garantia de não estragar o ficheiro não é recusar o formato, é ler estritamente.** O leitor usa `serde_json`, que rejeita todas as extensões JSON5. Um ficheiro com comentários ou vírgulas finais falha o parse, nada é escrito, e ele fica byte a byte intacto. O caso normal, que é JSON estrito e é o que o OpenClaw escreve, fica protegido. Há um teste para cada um dos dois lados.

**O que ainda falta:** o Goose guarda os servidores em YAML, e o escritor JSON não lhe pode tocar. Para ele e para o Aider o caminho é o `innerwarden contain`, que os protege sem precisar de cooperação nenhuma, e é o que o `install` recomenda.

Nota técnica: o OpenClaw não ganha hook, e não é disso que precisa. Os eventos dele são de sessão e mensagem, nenhum vê um comando shell proposto, e o `PreToolUse` que expõe é só um relay do harness por baixo. O proxy MCP é o mecanismo certo.

## 8. Comandos

```
check      analisa um comando (advisory)
serve      servidor loopback de veredictos (advisory)
proxy      proxy MCP bloqueante (default: guard)
hook       adaptador PreToolUse do Claude Code (bloqueia com exit 2)
contain    corre um agente isolado (bubblewrap / sandbox-exec)
install    escreve o hook no ~/.claude/settings.json (só claude-code)
uninstall  remove o hook, e opcionalmente config e binário
setup      assistente interativo, protege em dry run por omissão
agents     lista agentes detetados na máquina
enforce    passa os agentes protegidos para modo bloqueante
dry-run    (alias monitor) passa para modo observação
allow      autoriza um padrão de comando
mute       silencia um alerta
notify     configura Telegram/Slack/Discord/webhook
graph      consulta o grafo de decisões
dashboard  abre o dashboard local
llm        configura a segunda opinião por LLM
upgrade    atualiza o binário
```

## 9. O dashboard, e porque parecem dois

**Não são dois dashboards.** O código da UI é um só, o crate `dashboard-kit` deste repo. O dashboard Enterprise é **composto** a partir dele: 54 ficheiros deste repo mais 14 do Active Defence, com 1 override. Não é fork nem reimplementação.

O que difere é quem serve:

| | Community | Active Defence |
|---|---|---|
| Porta | 8788 | 8787 |
| Autenticação | nenhuma, só loopback | autenticado |
| O que serve | a UI e rotas de leitura | a UI **e** a API **e** os veredictos, tudo no mesmo servidor |

**É daqui que vem a colisão de portas do ponto 5.** Este produto separa por papel: veredictos em 8787 (`serve`), UI em 8788 (`dashboard`). O Active Defence junta tudo em 8787. Logo a porta da *API de veredictos* daqui bate com a porta do *tudo* de lá. As duas UIs nunca colidem.

Dito de outra forma: hoje as portas significam **produto**, quando deviam significar **papel**. Com 8787 a ser o cérebro e 8788 a ser a UI, é o Active Defence servir a UI em 8787 que é a anomalia.

## 10. Privacidade

Sem conta. O guard não envia nada para fora da máquina. Instalação por `curl | sh`, `cargo install` ou build a partir do source não envia nada de todo.

---

## 11. Pontos por esclarecer

Coisas que encontrei no código e que me parecem incoerentes. Não as corrigi, porque a decisão é do operador.

1. 🔴 **O Active Defence substitui a porta de entrada em vez de a estender, e isso apaga a camada gratuita.**

   O desenho correto está implementado aqui: `innerwarden` é o binário deste repo e reencaminha o que não conhece para o `innerwarden-ctl`. Mas o instalador do Active Defence coloca o **`ctl`** em `/usr/local/bin/innerwarden`. Nesse momento a porta de entrada deixa de ser o Community, o reencaminhamento nunca acontece, e os verbos gratuitos desaparecem.

   Verificado na Oracle a 2026-08-05, com o Active Defence instalado:

   ```
   /usr/local/bin/innerwarden      2751ff28f322c4fc
   /usr/local/bin/innerwarden-ctl  2751ff28f322c4fc   ← o mesmo binário

   innerwarden check     FALHA
   innerwarden hook      FALHA
   innerwarden proxy     FALHA
   innerwarden contain   FALHA
   innerwarden agents    FALHA
   ```

   Ou seja: **quem paga fica sem a proteção do agente pela linha de comandos**. É o oposto de proteção total. A correção é o instalador do Active Defence deixar de escrever por cima do `innerwarden` e passar a instalar apenas `innerwarden-ctl`, garantindo que o binário Community está presente como porta de entrada.

2. 🔴 **Verbos partilhados nunca chegam ao Active Defence.** O reencaminhamento só acontece para verbos que este binário **não** conhece. `setup`, `dashboard`, `upgrade` e `uninstall` existem dos dois lados, por isso são sempre tratados aqui e a versão do Active Defence fica inalcançável. Além disso `agents` (aqui) e `agent` (lá) são nomes diferentes para a mesma ideia.

   **Metade resolvida a 2026-08-05, do lado de cá.** A sobreposição deixou de ser acidente da ordem do `match` e passou a estar nomeada (`SHARED_VERBS`), e existe uma saída explícita: `innerwarden host <verbo>` corre sempre o verbo do Active Defence. Nenhum verbo do host fica inalcançável, e não há ambiguidade sobre qual camada responde.

   **Fica em aberto a decisão de produto**, que é tua: para cada um dos quatro verbos partilhados, se deve ser sempre local, sempre reencaminhado, ou local que se enriquece quando o Active Defence está presente. O `host` garante o acesso; não decide a ergonomia.

3. 🟠 **O proxy MCP: o motor está no sítio certo, a porta de entrada é que está duplicada.**

   **Não há código repetido.** O motor vive só aqui, em `crates/agent-guard/src/mcp_proxy/`, e o Active Defence importa-o. Zero cópias lá. Isto está certo e é coerente com a divisão por camadas: inspecionar chamadas MCP é ver o que o agente propõe, portanto é camada do utilizador, portanto é Community.

   O que está duplicado é o **comando** e, pior, o **default**:

   | | comando | default |
   |---|---|---|
   | Community | `innerwarden proxy` | `guard`, ou seja **bloqueia** (`main.rs:817`) |
   | Active Defence | `innerwarden agent proxy` | `advisory`, ou seja **não bloqueia** (`cli.rs:680`) |

   Consequência: quem passa pelo comando do Active Defence fica, por omissão, **menos protegido do que um utilizador gratuito**. Mesmo motor, postura contrária, e a postura fraca é a do produto pago.

   Se o proxy MCP é camada do Community, o Active Defence não devia ter verbo próprio: `innerwarden proxy` devia ser sempre o daqui, com o default `guard`. Isso depende do ponto 1 estar resolvido, porque hoje numa máquina paga o `innerwarden proxy` nem sequer existe.

4. 🔴 **O hook está implementado duas vezes, com posturas de falha opostas, e as duas escrevem no mesmo sítio.**

   | | Community | Active Defence |
   |---|---|---|
   | Forma | o próprio binário, em processo | script bash gerado |
   | Dependências | nenhuma | `curl` **e** `python3` |
   | Onde decide | localmente | faz curl a `/api/agent/check-command` |
   | Se algo falhar | deixa passar | **bloqueia tudo** (exit 2) |

   Os dois escrevem no mesmo `PreToolUse:Bash` do `~/.claude/settings.json`.

   ### Porquê que cada um escolheu o que escolheu

   Nenhum está a ser descuidado. O do Active Defence falha fechado **porque não tem análise local nenhuma**: é um script mudo, e se o endpoint não responde ele não sabe nada sobre o comando, portanto bloquear é a única escolha segura. O daqui deixa passar porque o que ele deixa passar é uma tool call *sem comando* ou um payload que não percebeu, e travar aí só entalava o agente sem ganhar segurança.

   ### Proposta

   **Um hook só: este.** O hook é camada do agente, portanto é Community, pela mesma lógica do proxy MCP.

   1. `innerwarden hook` continua a ser o único instalado, e **analisa sempre localmente**, sem depender de daemon nem de rede.
   2. Quando o Active Defence está presente e responde, o hook **consulta-o também**, e usa o veredicto mais severo dos dois. O que o produto pago acrescenta é contexto de host, correlação e inteligência de ameaça, não um segundo hook.
   3. Se o Active Defence não responder, **degrada para o veredicto local** e regista que degradou. Não bloqueia tudo.

   O ponto 3 é o que resolve o conflito, e resolve-o sem perder segurança: o fail-closed do Active Defence existe porque hoje o remoto é o **único** filtro. A partir do momento em que a análise local corre sempre, o Active Defence estar em baixo deixa de abrir portão nenhum, passa só a perder enriquecimento. Bloquear todos os comandos porque o agente reiniciou é custo puro.

   Para quem quiser mesmo a postura rígida, isso passa a ser uma opção explícita (`--require-host`), não o default silencioso.

   Ganha-se ainda tirar do caminho crítico duas dependências que hoje podem não existir: num container sem `python3`, o hook do Active Defence falha fechado e **bloqueia todo o trabalho do agente**.

5. 🟠 **A porta 8787 colide, e o resultado é imprevisível.**

   | porta | quem usa |
   |---|---|
   | **8787** | `innerwarden serve` daqui (`127.0.0.1:8787`) **e** o dashboard/API do Active Defence (`0.0.0.0:8787` em produção) |
   | 8788 | o dashboard local daqui |

   Os dois servem a **mesma rota**, `POST /api/agent/check-command`. Como `0.0.0.0` inclui o loopback, não é uma partilha: é uma corrida. Quem arrancar primeiro fica com a porta e o outro falha a ligar, ou, se houver reuso de porta, os pedidos dividem-se de forma imprevisível. No pior caso o hook do produto pago recebe um veredicto do Community, sem contexto de host, e ninguém dá por isso.

   ### Proposta

   Tratar `/api/agent/check-command` como o que é: um **contrato**, não uma funcionalidade de um produto. Uma máquina, um cérebro, um dono da porta.

   1. **8787 é a porta do contrato.** Quem for o cérebro naquela máquina serve-a.
   2. Se o Active Defence estiver instalado, **a porta é dele**, porque o veredicto dele é mais rico.
   3. O `serve` daqui **deteta isso e recusa-se a arrancar**, dizendo que o Active Defence já serve o contrato, em vez de morrer com um erro de bind ou, pior, de o sombrear em silêncio.
   4. Sem Active Defence, o `serve` daqui fica dono da porta, como hoje.

   Nota: com a proposta do ponto 4 aplicada, a porta deixa de estar no caminho crítico. O hook passa a analisar localmente e a porta serve só para enriquecer, o que torna toda esta colisão muito menos perigosa.

6. 🟠 **As regras ATR não cobrem a superfície shell, e é trabalho de corpus, não de código.**

   A ligação está correta: o `check` chama `engine.check_context(AtrContext::shell_command(...))`. O filtro é este (`rules.rs:390`):

   ```rust
   fn source_matches(declared: &str, actual: AtrSource) -> bool {
       actual == AtrSource::Any || declared.is_empty()
           || declared == "any" || declared == actual.as_str()
   }
   ```

   E o que as 71 regras declaram como origem:

   ```
   30  llm_io            27  tool_call         6  mcp_exchange
    4  multi_agent_comm   2  agent_communication
    1  memory_access      1  context_window
   ```

   **Nenhuma declara `shell_command`. Nenhuma declara `any`.** Logo, no caminho shell, as 71 são descartadas antes de qualquer regex correr. Zero matches por construção. Confirmado empiricamente: `rm -rf /`, `curl | bash` e `nc -e /bin/sh` dão todos `atr=0`, bloqueados por outros sinais.

   **O ATR não está morto.** Funciona nas superfícies para que foi escrito: as 33 regras de `tool_call` + `mcp_exchange` estão vivas no proxy MCP, e as 30 de `llm_io` também. O teste `embedded_corpus_matches_a_known_injection_payload` passa, via `check_user_input`.

   Quanto ao 71 contra 62: são 71 vendoradas, 9 de `detection_tier: semantic` (sem executor) e por isso saltadas, sobram 62 compiláveis. Está documentado, o que engana é o help anunciar "71 regras ATR" ao lado do rastreio de comandos shell, onde nenhuma se aplica.

   **Tentei a correção óbvia a 2026-08-05 e medi o resultado.** Deixar `shell_command` satisfazer regras `tool_call` é semanticamente defensável, porque o contexto shell já preenche `tool_args`. Levou o benchmark de **0 para 44 falsos positivos em 86** comandos benignos, todos `deny`: proteger a própria chave com `chmod`, um `curl --fail ... -o release.tar.gz`, um `printf | perl -pe`. As regras ATR-2026-012 e 066 casam com quase qualquer texto shell que tenha um pipe ou um fetch, porque foram escritas para argumentos MCP estruturados.

   Revertido, e o achado ficou documentado na própria função. Um guardrail que nega metade do trabalho normal é desligado, e depois não protege nada.

   Para cobrir shell é preciso **escrever regras para linha de comandos** e medi-las contra o benchmark de benignos. **Nenhuma linha de Rust muda**, mas também não basta mudar a origem declarada das regras existentes.

7. ✅ **`registry.rs` e `session.rs` não eram código morto, era uma capacidade por ligar. Ligada a 2026-08-05.**

   O que são: `registry.rs` é o registo de agentes ligados (ID, política, rastreador por agente); `session.rs` é deteção de anomalia comportamental, com limites de 30 chamadas por minuto, 5 falhas e 3 acessos sensíveis por sessão. Ambos camada do agente, logo Community pela regra deste documento.

   **Porque nunca esteve ligado, e não era razão comercial:** o `SessionTracker` guarda `Instant`, que é monotónico e local ao processo, portanto não serializável. Serve um daemon. Mas o `innerwarden hook` é um processo que nasce, analisa uma tool call, responde e morre; um tracker em memória estaria vazio em todas as chamadas e "30 por minuto" nunca poderia ser observado. A forma do estado não encaixava na forma do processo.

   O que passou a existir:

   - `PersistedSession` no crate partilhado: a mesma lógica em milissegundos de relógio. **Reutiliza as mesmas constantes `MAX_*`**, para o grátis e o pago não divergirem.
   - `crates/cli/src/session_store.rs`: um JSON 0600 com TTL de 24h e teto de 64 sessões, chaveado pelo session id que o hook já lia do payload do agente. Best-effort por desenho: uma falha a ler ou escrever nunca entala uma tool call.
   - `apply_behaviour`: o alerta sobe `allow` para `review` e **nunca inventa um `deny`**, porque descreve a sessão e não aquele comando. Um agente rápido a fazer trabalho seguro não é um ataque. Um `deny` existente não é suavizado.

   **Correção ao que eu tinha escrito aqui:** disse que o `registry.rs` também devia ser ligado ao Community. Estava errado, e a evidência é a mesma que explicou o `session.rs`.

   O `registry.rs` é o modelo do **daemon**: `ConnectedAgent` guarda um pid, contadores vivos e um `SessionTracker` com janelas em `Instant`. Tudo isso pressupõe um processo que fica de pé a observar. E o CLI já responde à mesma pergunta numa forma que lhe serve: o `agent_policy` persiste **quais** agentes são protegidos e reconcilia-os, sem estado de processo vivo.

   Ligar os dois daria ao mesmo produto dois registos que discordam. Ficou anotado no cabeçalho do módulo para ninguém "corrigir" o aviso de código não usado ligando-o.
