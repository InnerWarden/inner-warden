/**
 * Restarting an agent is the person's step. An agent reads its hook or MCP
 * config only when it starts, so a step that changes that config is followed
 * by how to restart it, per agent, and why.
 *
 * The CLI sends these words with each agent (`restart`), and they are printed
 * as sent. These are the same words for a CLI that sends none. Nothing here
 * says an agent restarted, reloaded or picked a change up: the page cannot
 * know that, and only the person can do it.
 */
export type RestartWords = { how: string; why: string };

/** Why, for every agent. */
export const RESTART_WHY = "An agent reads its hook or MCP config only when it starts.";

const HOW: Record<string, string> = {
  "claude-code": "In Claude Code, type /exit, then run claude.",
  codex: "Quit Codex and start it again.",
};

/** How to restart an agent, by its id, or the generic words with its name. */
export function restartWords(agentId: string, displayName: string): RestartWords {
  return { how: HOW[agentId] ?? `Quit ${displayName} and start it again.`, why: RESTART_WHY };
}

/** The words the CLI sent for this agent, or these when it sent none. */
export function restartFor(agentId: string, displayName: string, served: RestartWords | undefined): RestartWords {
  return served ?? restartWords(agentId, displayName);
}

/** The whole note, as one sentence run: "If Codex is running, restart it after this step. Quit Codex ..." */
export function restartNote(displayName: string, words: RestartWords): string {
  return `If ${displayName} is running, restart it after this step. ${words.how} ${words.why}`;
}

/**
 * The commands that change an agent's hook or MCP config: the person restarts
 * the agent afterwards, because an agent reads that config only when it
 * starts. Every step whose command starts with one of these carries the
 * agent's restart words.
 */
export const CONFIG_CHANGING = ["innerwarden enforce", "innerwarden dry-run", "innerwarden install", "innerwarden agents connect"] as const;

export function changesAgentConfig(command: string | undefined): boolean {
  return command !== undefined && CONFIG_CHANGING.some((prefix) => command === prefix || command.startsWith(`${prefix} `));
}

/**
 * `observe install` writes a hook into the OpenClaw gateway, which loads its
 * hooks only when it starts; nothing here restarts it. Its restart, in the
 * same words as any other.
 */
export const GATEWAY_NAME = "the OpenClaw gateway";
export function gatewayRestart(): { agent: string; words: RestartWords } {
  return { agent: GATEWAY_NAME, words: restartWords("openclaw", GATEWAY_NAME) };
}
