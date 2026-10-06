/**
 * InnerWarden replies: how a Control UI turn ended, for `innerwarden observe`.
 *
 * The message hook (`innerwarden-attempts`) sees a Control UI message arrive
 * and never its reply: OpenClaw streams a `webchat` reply back over the
 * gateway connection, fires no `message:sent` for it, and no internal hook
 * event marks the end of the turn. The typed plugin hook `agent_end` does. It
 * fires when an agent turn ends, with the turn's messages, whether it
 * succeeded and how long it ran (OpenClaw 2026.9.7), so this plugin reads the
 * SHAPE of the turn (did it call a tool, did it end with something said) and
 * hands one word to `innerwarden observe ended`, which closes the ask that
 * turn answered, if one is held for it.
 *
 * Only the session, the turn's run id and that word reach the CLI. The
 * conversation's text never leaves the gateway through this plugin.
 *
 * Which turn: the CLI matches the run id to the id of the message that started
 * the turn (the Control UI sends each message with the id its turn then runs
 * under), so a turn still answering an earlier message never closes a newer
 * ask. Which trigger: only a turn a person started. `agent_end` takes no
 * trigger filter (the host honours `eligibleTriggers` for `before_agent_reply`
 * only), so this checks `ctx.trigger` itself: a heartbeat or cron turn in the
 * same session never closes an ask.
 *
 * It observes and never decides. Every failure is swallowed, because a
 * telemetry plugin must never be able to break the gateway it runs inside.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_ID = "innerwarden-replies";
/** Hard cap on one call, so a wedged binary cannot pile up processes. */
const TIMEOUT_MS = 4000;
/**
 * How long the report waits. The gateway awaits neither this hook nor the
 * message hook's `observe inbound` call, so a quick turn can end before that
 * call has finished holding the ask; the report goes after it. An ask still
 * not held by then is settled by the message hook's own timer, as before.
 */
const REPORT_DELAY_MS = 3000;
/** The turns this reads: a person's, never a heartbeat's or a cron job's. */
const TRIGGER = "user";
/** The channel whose replies OpenClaw never reports to internal hooks. */
const UNREPORTED_REPLY_CHANNEL = "webchat";
/** OpenClaw's record of a tool run inside a tool (a nested call). */
const NESTED_TOOL_ACTIVITY = "openclaw.nested-tool.v1";
/**
 * How far before the turn's start (now less its duration) a message may be
 * stamped and still be read as the turn's own. The two clock readings are the
 * same process's, a few milliseconds apart.
 */
const TURN_START_SLACK_MS = 250;

const pluginDir = path.dirname(fileURLToPath(import.meta.url));

function resolveBinary() {
  const fromEnv = process.env.IW_GUARD_BIN?.trim();
  if (fromEnv) return fromEnv;
  try {
    const raw = readFileSync(path.join(pluginDir, "bin.json"), "utf8");
    const bin = JSON.parse(raw)?.bin;
    if (typeof bin === "string" && bin.trim()) return bin.trim();
  } catch {
    // No pinned path: fall back to PATH.
  }
  return "innerwarden";
}

function run(bin, args) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { stdio: ["ignore", "ignore", "ignore"] });
    } catch {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already gone.
      }
    }, TIMEOUT_MS);
    const done = () => {
      clearTimeout(timer);
      resolve();
    };
    child.on("error", done);
    child.on("close", done);
  });
}

const text = (value) => (typeof value === "string" ? value : "");

function isPrompt(message) {
  return message?.role === "user" && message.runtimeContextCarrier !== true;
}

function callsATool(message) {
  if (message?.role === "toolResult") return true;
  if (message?.customType === NESTED_TOOL_ACTIVITY) return true;
  return (
    message?.role === "assistant" &&
    Array.isArray(message.content) &&
    message.content.some((block) => block?.type === "toolCall")
  );
}

function saysSomething(message) {
  const content = message?.content;
  if (typeof content === "string") return content.trim() !== "";
  return (
    Array.isArray(content) &&
    content.some((block) => block?.type === "text" && text(block.text).trim() !== "")
  );
}

/**
 * How the turn ended: `replied`, `used_tools` or `no_reply`, or `undefined`
 * when the turn's own messages cannot be told apart from the session's.
 *
 * `event.messages` is the session as the model saw it, earlier turns
 * included, so the turn is bounded twice and the wider bound wins: from the
 * first message stamped at or after the turn began (`now` less `durationMs`),
 * and from just after the last message a person sent. A tool call anywhere in
 * the turn makes it `used_tools`, whatever was said after it. A reply is the
 * turn's last assistant message, after the person's last message, with text
 * in it and no error. Exported for the tests.
 */
export function turnEnd(event, now) {
  const messages = Array.isArray(event?.messages) ? event.messages : [];
  if (messages.length === 0) return undefined;
  let lastPrompt = -1;
  messages.forEach((message, index) => {
    if (isPrompt(message)) lastPrompt = index;
  });
  const duration = event?.durationMs;
  let firstOfTurn = -1;
  if (typeof duration === "number" && Number.isFinite(duration) && duration >= 0) {
    const startedAt = now - duration - TURN_START_SLACK_MS;
    firstOfTurn = messages.findIndex(
      (message) => typeof message?.timestamp === "number" && message.timestamp >= startedAt,
    );
  }
  const candidates = [firstOfTurn, lastPrompt === -1 ? -1 : lastPrompt + 1].filter((i) => i >= 0);
  if (candidates.length === 0) return undefined;
  const turn = messages.slice(Math.min(...candidates));
  if (turn.some(callsATool)) return "used_tools";
  if (event.success !== true) return "no_reply";
  const reply = turn.findLast((message) => message?.role === "assistant");
  const afterPrompt = reply !== undefined && messages.lastIndexOf(reply) > lastPrompt;
  if (
    !afterPrompt ||
    reply.stopReason === "error" ||
    reply.stopReason === "aborted" ||
    !saysSomething(reply)
  ) {
    return "no_reply";
  }
  return "replied";
}

/** The channel a turn ran on, as the hook context names it. */
function channelOf(ctx) {
  return text(ctx?.messageProvider) || text(ctx?.channel);
}

/** The `agent_end` handler. Exported for the tests. */
export function onAgentEnd(event, ctx) {
  const now = Date.now();
  if (ctx?.trigger !== TRIGGER) return;
  if (channelOf(ctx) !== UNREPORTED_REPLY_CHANNEL) return;
  const session = text(ctx?.sessionKey);
  const runId = text(ctx?.runId) || text(event?.runId);
  if (!session || !runId) return;
  const ended = turnEnd(event, now);
  if (!ended) return;
  const bin = resolveBinary();
  // Not awaited, and unref'd: the gateway never waits on telemetry, and a
  // report lost to a restart costs only this turn's outcome, which the
  // message hook's timer still records as not seen.
  const timer = setTimeout(
    () => run(bin, ["observe", "ended", "--session", session, "--run", runId, "--turn", ended]),
    REPORT_DELAY_MS,
  );
  timer?.unref?.();
}

export default {
  id: PLUGIN_ID,
  name: "InnerWarden replies",
  description:
    "Tells innerwarden observe how a Control UI turn ended. Observes only; never changes a turn.",
  register(api) {
    api.on("agent_end", onAgentEnd);
  },
};
