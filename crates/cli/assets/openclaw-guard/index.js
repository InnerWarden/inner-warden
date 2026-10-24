/**
 * InnerWarden guard: OpenClaw's own tools, screened before they run.
 *
 * OpenClaw runs commands and changes files through tools of its own (`exec`,
 * `process`, `write`, `edit`, `apply_patch`), not through an MCP server, so
 * the MCP proxy `innerwarden agents connect openclaw` wires never sees them.
 * OpenClaw 2026.9.7 asks every plugin's `before_tool_call` hook before one of
 * those tools runs. This plugin hands each call to `innerwarden openclaw
 * screen`, which judges it with the screening the Claude Code hook uses (and
 * asks InnerWarden Pro's check-command where Pro is installed), records it,
 * and answers allow, review or deny.
 *
 * Monitor (the default) records and changes nothing. Enforce:
 *
 * - deny: the call is refused. The model hears "Refused by InnerWarden." and
 *   nothing else, so it cannot learn which rule fired.
 * - review: the person is asked (allow once or deny). Nobody answering in
 *   time is a refusal.
 * - allow: the call runs as it was screened.
 *
 * What was screened is what runs. OpenClaw lets the last hook's `params`
 * replace the call, and hands every handler a copy of the original call, so
 * this plugin answers twice: first (the highest priority), to refuse or to
 * ask before any other handler, which freezes the call it screened under the
 * approval; and last (the lowest priority), with the copy it screened, so a
 * rewrite another plugin made in between does not run in its place. A
 * rewrite that a plugin froze under an approval of its own before this
 * plugin answered cannot be undone here; `after_tool_call` sees what ran,
 * and a call that ran other than as screened is recorded as such.
 *
 * The conversation never leaves the gateway through this plugin: the tool's
 * name, its parameters (without the content a write carries), the chat's
 * session key and whether the host says the sender is the owner reach the
 * CLI. A screening that fails is a refusal in enforce and a call recorded
 * as not screened in monitor.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_ID = "innerwarden-guard";
/** The tools screened here, as OpenClaw names them. */
export const SCREENED_TOOLS = ["exec", "process", "write", "edit", "apply_patch"];
/** All the model is ever told about a refusal. */
export const MODEL_REASON = "Refused by InnerWarden.";
/**
 * One screening, under the gateway's 15 s budget for a `before_tool_call`
 * hook: the CLI's own reading, and InnerWarden Pro's (at most 3 s each)
 * where Pro is installed.
 */
const SCREEN_TIMEOUT_MS = 10_000;
/** A report after the call, which nothing waits on. */
const REPORT_TIMEOUT_MS = 4000;
/** How long the person has to answer an approval card. */
const APPROVAL_TIMEOUT_MS = 120_000;
/** The most stdin one screening sends. */
const MAX_INPUT_BYTES = 512 * 1024;
/** The most of a tool's result read for a refusal the kernel made. */
const MAX_RESULT_CHARS = 64 * 1024;
/** Calls remembered between their screening and their end. */
const MAX_REMEMBERED = 256;
/** First and last among `before_tool_call` handlers. */
const FIRST = Number.POSITIVE_INFINITY;
const LAST = Number.NEGATIVE_INFINITY;
/** What a program the kernel refused to start leaves in its result. */
const KERNEL_REFUSAL = /permission denied|operation not permitted|exit code:? 126\b|"exitCode":\s*126\b/i;

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

/** The plugin's mode: anything but `enforce` is monitor. */
export function modeOf(config) {
  return config?.mode === "enforce" ? "enforce" : "monitor";
}

/**
 * Run the CLI with `input` on stdin; resolve with its stdout, or undefined
 * when it could not run, timed out or was aborted.
 */
function run(bin, args, input, timeoutMs, signal) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { stdio: ["pipe", "pipe", "ignore"] });
    } catch {
      resolve(undefined);
      return;
    }
    let out = "";
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", onAbort);
      resolve(value);
    };
    const kill = () => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Already gone.
      }
    };
    const onAbort = () => {
      kill();
      finish(undefined);
    };
    const timer = setTimeout(() => {
      kill();
      finish(undefined);
    }, timeoutMs);
    signal?.addEventListener?.("abort", onAbort, { once: true });
    child.stdout.on("data", (chunk) => {
      if (out.length < 64 * 1024) out += chunk;
    });
    child.on("error", () => finish(undefined));
    child.on("close", (code) => finish(code === 0 ? out : undefined));
    try {
      child.stdin.on("error", () => {});
      child.stdin.end(input.slice(0, MAX_INPUT_BYTES));
    } catch {
      finish(undefined);
    }
  });
}

const text = (value) => (typeof value === "string" ? value : "");

/**
 * The parameters the CLI needs: everything but the content a write or an
 * edit carries. Where a call writes is judged, never what it writes.
 */
export function paramsForScreening(toolName, params) {
  if (!params || typeof params !== "object") return {};
  if (toolName === "write" || toolName === "edit") {
    const { content: _content, edits: _edits, oldText: _old, newText: _new, ...rest } = params;
    return rest;
  }
  return params;
}

/** One call as the CLI reads it (`openclaw_guard::ToolCall`). */
export function callFor(event, ctx) {
  const owner = ctx?.requester?.senderIsOwner;
  return {
    tool: text(event?.toolName),
    params: paramsForScreening(event?.toolName, event?.params),
    derived_paths: Array.isArray(event?.derivedPaths) ? event.derivedPaths.filter((p) => typeof p === "string") : [],
    session: text(ctx?.sessionKey),
    tool_call_id: text(event?.toolCallId) || text(ctx?.toolCallId),
    run_id: text(event?.runId) || text(ctx?.runId),
    cwd: text(ctx?.cwd),
    // `requester.channel` is where the turn came from (`webchat` for the
    // Control UI, `telegram`, ...); `channelId` can be the session key.
    channel: text(ctx?.requester?.channel) || text(ctx?.channelId),
    ...(typeof owner === "boolean" ? { owner } : {}),
  };
}

/** Key order removed, so two copies of one call compare equal. */
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, stable(value[key])]),
  );
}

export function sameCall(left, right) {
  try {
    return JSON.stringify(stable(left ?? {})) === JSON.stringify(stable(right ?? {}));
  } catch {
    return false;
  }
}

/** The plugin, built over the CLI it calls and the clock (both swapped in tests). */
export function createGuard({ mode, bin = resolveBinary(), now = () => Date.now(), runCli = run } = {}) {
  const enforce = mode === "enforce";
  /** toolCallId -> what was screened, and when. */
  const screened = new Map();
  const remember = (id, entry) => {
    if (!id) return;
    screened.set(id, entry);
    while (screened.size > MAX_REMEMBERED) screened.delete(screened.keys().next().value);
  };
  const report = (args, body) => {
    // Not awaited: nothing waits on a report, and a lost one costs a record.
    runCli(bin, args, JSON.stringify(body), REPORT_TIMEOUT_MS).catch?.(() => {});
  };

  async function screen(event, ctx) {
    if (!SCREENED_TOOLS.includes(event?.toolName)) return undefined;
    const call = callFor(event, ctx);
    const started = now();
    remember(call.tool_call_id, { params: event?.params, started, session: call.session, tool: call.tool });
    const out = await runCli(
      bin,
      ["openclaw", "screen", "--mode", enforce ? "enforce" : "monitor"],
      JSON.stringify(call),
      SCREEN_TIMEOUT_MS,
      ctx?.abortSignal,
    );
    let answer;
    try {
      answer = out ? JSON.parse(out) : undefined;
    } catch {
      answer = undefined;
    }
    if (!enforce) return undefined;
    const decision = answer?.decision;
    if (decision === "allow") return undefined;
    if (decision === "review" && answer?.card) {
      const card = answer.card;
      return {
        // The copy that was screened: under the approval no later handler
        // can change it.
        params: event.params,
        requireApproval: {
          title: text(card.title) || "InnerWarden: allow this call?",
          description: text(card.description),
          severity: card.severity === "critical" ? "critical" : "warning",
          timeoutMs: APPROVAL_TIMEOUT_MS,
          timeoutReason: MODEL_REASON,
          allowedDecisions: ["allow-once", "deny"],
          onResolution: (resolution) =>
            report(["openclaw", "resolved", "--decision", text(resolution) || "timeout"], {
              call,
              record: answer.record ?? null,
            }),
        },
      };
    }
    // A deny, a review with no card, or no answer at all: refused.
    return { block: true, blockReason: MODEL_REASON };
  }

  function restore(event) {
    // Last: the call that runs is the copy that was screened, whatever a
    // plugin in between returned. Monitor changes nothing.
    if (!enforce || !SCREENED_TOOLS.includes(event?.toolName)) return undefined;
    return { params: event.params };
  }

  function ended(event, ctx) {
    const id = text(event?.toolCallId);
    const entry = id ? screened.get(id) : undefined;
    if (!entry) return;
    screened.delete(id);
    const rewritten = !sameCall(entry.params, event?.params);
    let refusedLooking = false;
    if (entry.tool === "exec" || entry.tool === "process") {
      let result = "";
      try {
        result = JSON.stringify(event?.result ?? "").slice(0, MAX_RESULT_CHARS);
      } catch {
        result = "";
      }
      refusedLooking = KERNEL_REFUSAL.test(result) || KERNEL_REFUSAL.test(text(event?.error));
    }
    if (!rewritten && !refusedLooking) return;
    report(["openclaw", "ran"], {
      session: entry.session || text(ctx?.sessionKey),
      tool: entry.tool,
      tool_call_id: id,
      started_ms: entry.started,
      ended_ms: now(),
      rewritten,
    });
  }

  return { screen, restore, ended };
}

export default {
  id: PLUGIN_ID,
  name: "InnerWarden guard",
  description:
    "Screens OpenClaw's own exec, process, write, edit and apply_patch calls with InnerWarden before they run.",
  register(api) {
    const guard = createGuard({ mode: modeOf(api?.pluginConfig) });
    api.on("before_tool_call", guard.screen, {
      matcher: SCREENED_TOOLS,
      priority: FIRST,
      registrationId: "screen",
    });
    api.on("before_tool_call", guard.restore, {
      matcher: SCREENED_TOOLS,
      priority: LAST,
      registrationId: "screened-copy",
    });
    api.on("after_tool_call", guard.ended, { matcher: SCREENED_TOOLS, registrationId: "ended" });
  },
};
