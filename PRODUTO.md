# InnerWarden Community

> Documento de produto. Descreve o que este binário é, o que faz, e — tão
> importante quanto — o que não faz. Datado de 2026-08-06, workspace `1.1.0`.
> Cada afirmação aqui foi verificada contra o código ou contra uma execução
> real; onde há limite, o limite está escrito.

---

## 1. O que é, em uma frase

Um guardrail em tempo de execução para agentes de IA: examina o que o agente
**tenta fazer** — comandos de shell e chamadas MCP/tool — antes de acontecerem,
e devolve um veredito: `allow`, `review` ou `deny`.

Não é uma ferramenta para programadores protegerem código. É uma ferramenta
para proteger **o agente**, seja ele o OpenClaw, o Claude Code, o Cursor, o
Codex ou o Gemini CLI.

---

## 2. A camada onde atua

Atua na **camada do utilizador**: o processo do agente, os ficheiros de
configuração dele, os servidores MCP que ele chama, os comandos que ele propõe.

**Não vê** drivers, kernel, syscalls, nem nada que não passe pelo agente. Um
processo que arranque fora do agente é invisível para este binário. Isso não é
um defeito por corrigir: é onde esta camada acaba, e dizê-lo é mais útil do que
sugerir cobertura que não existe.

O comando `innerwarden host <verbo>` existe para alcançar a camada de host
quando ela está instalada na máquina. Sem ela instalada, diz isso e não finge.

---

## 3. O que NÃO é

- **Não é um antivírus.** Não faz varrimento de ficheiros à procura de assinaturas.
- **Não é um sandbox por omissão.** O `contain` isola quando o invocas; o
  guardrail normal aconselha e bloqueia, não confina.
- **Não é infalível contra um agente que deixe de cooperar.** O hook e o proxy
  MCP dependem de o agente os chamar. Um agente que os contorne não é travado
  por eles. Está escrito assim no código e deve estar escrito assim aqui.
- **Não envia nada para fora da máquina.** Ver §8.

---

## 4. Forma física

Um binário, `innerwarden`. Sem daemon, sem serviço, sem base de dados, sem
dependência de rede para funcionar.

| Canal | Comando |
|---|---|
| npm (recomendado, todos os SO) | `npm install -g innerwarden` |
| macOS e Linux | `curl -fsSL https://innerwarden.com/free \| sh` |
| Debian/Ubuntu | `sudo apt install ./innerwarden_<v>_amd64.deb` |
| Fedora/RHEL/Rocky | `sudo dnf install .../innerwarden-<v>-1.x86_64.rpm` |
| Windows | `irm https://innerwarden.com/free.ps1 \| iex` |

Cada binário publicado traz `.sha256` e `.sig` (Ed25519 sobre o digest). O
instalador verifica ambos contra uma chave fixada dentro dele, e o
`innerwarden upgrade` verifica contra a chave compilada no binário que está a
correr. Detalhe de manutenção em [DISTRIBUTION.md](DISTRIBUTION.md).

Linux e macOS são de primeira classe. Windows é suportado e, desde a 1.1.0,
corre a suíte de testes completa no CI — o que revelou e corrigiu dois defeitos
que existiam desde a 1.0.0: escrita de configuração impossível e dashboard que
não servia nada.

---

## 5. O que bloqueia de facto, e o que é só opinião

Esta distinção é a mais importante do documento.

### Bloqueia

- **Hook do Claude Code** (`innerwarden install claude-code`): corre antes de
  cada comando de shell proposto e sai com código não-zero num `deny`, o que
  impede a execução.
- **Proxy MCP** (`innerwarden proxy`, e o wiring automático de `agents
  connect`): recusa uma `tools/call` proibida inline, sem ela chegar ao servidor.
- **AI Jail** (`innerwarden contain`): corre o agente num perfil restrito, onde
  uma ação negada é impedida em vez de apenas assinalada. Linux (bubblewrap) e
  macOS (sandbox-exec) apenas; em Windows recusa-se a correr em vez de fingir
  que isola.

### Só aconselha

- `innerwarden check <comando>`: examina e devolve o veredito. Não executa nem
  impede nada — quem decide é quem chamou.
- Qualquer agente sem hook e sem MCP: o veredito existe, a aplicação não.

**Honestidade sobre o hook:** ele não é *fail-closed*. Entrada que não consegue
interpretar, ou uma chamada de tool sem comando de shell, passa — de propósito.
Um guardrail que entala todas as chamadas não-Bash é desinstalado numa hora, e
um guardrail desinstalado não protege ninguém.

---

## 6. Que agentes protege, e por que mecanismo

Nem todos os agentes oferecem a mesma superfície. O produto diz qual é a de
cada um em vez de dar uma resposta única:

| Agente | Mecanismo | Comando |
|---|---|---|
| Claude Code | hook PreToolUse | `innerwarden install claude-code` |
| Cursor | wiring MCP | `innerwarden agents connect cursor` |
| Codex CLI | wiring MCP (o `notify` dele dispara **depois**, não pode bloquear) | `innerwarden agents connect codex` |
| Gemini CLI | wiring MCP | `innerwarden agents connect gemini` |
| OpenClaw | wiring MCP (servidores em `mcp.servers` aninhado) | `innerwarden agents connect openclaw` |
| Qualquer cliente MCP | proxy manual | `innerwarden proxy -- <servidor>` |
| Goose, Aider, OpenHands, Windsurf, Cline | sem superfície cooperativa confirmada | `innerwarden contain -- <comando>` |

`innerwarden install` sem argumento deteta o que está na máquina e imprime o
mecanismo de cada um. Todo o wiring é reversível com `agents disconnect`, e
preserva o resto da configuração do agente.

A última linha da tabela é deliberada. Ligar um agente exige conhecer o
caminho **confirmado** da configuração MCP dele; adivinhar significa escrever
no ficheiro errado, que é a única falha que este módulo não pode ter.

---

## 7. Comandos

```
check <cmd>          examina um comando e devolve o veredito (não executa)
hook                 lê uma chamada de tool no stdin; sai não-zero num deny
proxy -- <servidor>  proxy MCP à frente de um servidor
install [agente]     instala o hook; sem argumento, deteta e explica
agents               lista, connect, disconnect
contain -- <cmd>     corre isolado (Linux/macOS)
setup                configuração guiada
dashboard            UI local só de leitura (127.0.0.1:8788)
serve                contrato local de check-command (127.0.0.1:8787)
graph                o registo local: narrativa, --stats, --json
allow / mute         supressões, registadas no grafo
llm                  segunda opinião opcional por modelo local
notify               canais de notificação
upgrade              atualiza, verificando assinatura
host <verbo>         alcança a camada de host, se instalada
```

---

## 8. Privacidade

O guardrail **não envia nada para fora da máquina**. O registo local vive em
`~/.config/innerwarden/graph.json`; segredos comuns são redigidos antes de lá
entrarem. O dashboard serve só em loopback e é só de leitura.

Duas exceções, ambas explícitas: o instalador `curl | sh` envia **um** ping
anónimo de instalação (versão + SO + arquitetura; sem IP, sem dados de host;
`INNERWARDEN_NO_TELEMETRY=1` desliga), e a segunda opinião por LLM só contacta
o endpoint que **tu** configuras. Uma instalação por `cargo` ou a partir do
código-fonte não envia nada.

---

## 9. Dashboard

`innerwarden dashboard` serve em `127.0.0.1:8788`. A porta 8787 é outra coisa:
o contrato local de `check-command` do `serve`. São superfícies diferentes e o
produto trata-as como tal.

O dashboard mostra o que o registo local tem e, desde a 1.1.0, diz quando
**deixou de registar** em vez de mostrar dados cada vez mais antigos sem
explicação (`/api/guard/record-health` e `innerwarden graph`).
