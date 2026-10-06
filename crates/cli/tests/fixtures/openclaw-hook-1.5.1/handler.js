/**
 * InnerWarden conversation-attempt observer for OpenClaw.
 *
 * OpenClaw's internal hook events are command / session / agent / gateway /
 * message. None of them sees a proposed shell command, which is why the guard
 * enforces through MCP. The message family is a different thing: it sees the
 * inbound user text (`message:received`) and the outbound assistant reply
 * (`message:sent`), which is exactly what a refused attack attempt looks like.
 *
 * This handler observes and never decides. It cannot cancel a message and does
 * not try to: it hands the text to `innerwarden observe`, which does the
 * scoring and the recording. Every failure here is swallowed, because a
 * telemetry hook must never be able to break the gateway it runs inside.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Hard cap on one call, so a wedged binary cannot hold a gateway turn. */
const TIMEOUT_MS = 4000;
/** Text beyond this is not needed to judge an ask, and is not worth the pipe. */
const MAX_INPUT_BYTES = 64 * 1024;

const hookDir = path.dirname(fileURLToPath(import.meta.url));

function resolveBinary() {
  const fromEnv = process.env.IW_GUARD_BIN?.trim();
  if (fromEnv) return fromEnv;
  try {
    const raw = readFileSync(path.join(hookDir, "bin.json"), "utf8");
    const bin = JSON.parse(raw)?.bin;
    if (typeof bin === "string" && bin.trim()) return bin.trim();
  } catch {
    // No pinned path: fall back to PATH.
  }
  return "innerwarden";
}

function run(bin, args, input) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(bin, args, { stdio: ["pipe", "ignore", "ignore"] });
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
    try {
      child.stdin.on("error", () => {});
      child.stdin.end(input.slice(0, MAX_INPUT_BYTES));
    } catch {
      done();
    }
  });
}

const text = (value) => (typeof value === "string" ? value : "");

const handler = async (event) => {
  if (event?.type !== "message") return;
  if (event.action !== "received" && event.action !== "sent") return;

  const context = event.context ?? {};
  const content = text(context.content);
  if (!content.trim()) return;

  const session = text(event.sessionKey);
  if (!session) return;

  const channel = text(context.channelId) || "unknown";
  const bin = resolveBinary();

  if (event.action === "received") {
    const sender = text(context.metadata?.senderId) || text(context.from);
    await run(
      bin,
      ["observe", "inbound", "--session", session, "--channel", channel, "--sender", sender],
      content,
    );
    return;
  }

  // A delivery that failed is not a reply the user ever saw, so it settles
  // nothing about what happened to the ask.
  if (context.success === false) return;
  await run(bin, ["observe", "reply", "--session", session, "--channel", channel], content);
};

export default handler;
