import { createElement, type ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CommunityScreenContext } from "../App";
import type { DashboardMeta } from "../api";
import overviewFixture from "../../tests/fixtures/community/overview.json";
import page1 from "../../tests/fixtures/community/decisions-page-1.json";
import byId from "../../tests/fixtures/community/decisions-by-id.json";
import historyFixture from "../../tests/fixtures/community/history.json";
import attemptsFixture from "../../tests/fixtures/community/history-attempts.json";
import protectionFixture from "../../tests/fixtures/community/protection.json";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import sessionsFixture from "../../tests/fixtures/community/sessions.json";
import suppressFixture from "../../tests/fixtures/community/suppress.json";
import baseMeta from "../../tests/fixtures/community/meta.json";
import { readAttemptsPage, readDecisionDetail, readDecisionsPage, readHistory, readProtection, readRecordHealth, readSessionsPage, readSuppressList } from "./api";
import { GENERIC_LINE, INSTALLED_LINE, TOUR_UPGRADE_LINE } from "./offers";
import { changesAgentConfig } from "./restart";
import { WITHHELD_WORDS } from "./words";

/**
 * The Community copy sweep (spec 16.1): what every Community page may say,
 * held over every source file in this folder and over the pages rendered
 * from the CLI's fixtures.
 *
 *  (a) none of the words a screen must never use;
 *  (b) the paid edition named only in the permitted sentences: the three
 *      offer sentences and the words that say which layer decided a command.
 *      An allow-list of what may be said, never a list of names;
 *  (c) no Title-Case "<Word> Guard" or "<Word> Gate", and no "kernel";
 *  (d) every step whose command changes an agent's config carries that
 *      agent's restart words beside it;
 *  (e) no em or en dash.
 */

/** Every source file in this folder, read through Vite so no node types are needed. */
const SOURCES: Record<string, string> = import.meta.glob(["./**/*.ts", "./**/*.tsx", "./**/*.css"], {
  query: "?raw",
  eager: true,
  import: "default",
});
const files = Object.entries(SOURCES).map(([path, text]) => ({ path: path.replace(/^\.\//, ""), text }));
const shipped = files.filter((file) => !file.path.includes(".test."));

/** An en or an em dash, built at run time so this file carries neither. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);

/** The source with its comments removed, so a comment that quotes retired copy is not read as copy. */
function withoutComments(source: string): string {
  let out = "";
  let mode: "code" | "line" | "block" | "single" | "double" | "template" = "code";
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];
    if (mode === "code") {
      if (character === "/" && next === "/") { mode = "line"; index += 1; continue; }
      if (character === "/" && next === "*") { mode = "block"; index += 1; continue; }
      if (character === "'") mode = "single";
      else if (character === '"') mode = "double";
      else if (character === "`") mode = "template";
      out += character;
    } else if (mode === "line") {
      if (character === "\n") { mode = "code"; out += character; }
    } else if (mode === "block") {
      if (character === "*" && next === "/") { mode = "code"; index += 1; }
      else if (character === "\n") out += character;
    } else if (character === "\\") {
      out += character + (next ?? "");
      index += 1;
    } else {
      if ((mode === "single" && character === "'") || (mode === "double" && character === '"') || (mode === "template" && character === "`")) mode = "code";
      out += character;
    }
  }
  return out;
}

/** Spec 10.5: never on a Community screen. */
const BANNED = /\b(protected|safe|secure|verified|proven|restarted|reloaded)\b|blocked threats|would have stopped|picked (it |a change |the change )?up/i;

describe("(a) the words a Community screen never uses", () => {
  it("are in no Community source, comments aside", () => {
    expect(shipped.length).toBeGreaterThan(20);
    for (const file of shipped) {
      withoutComments(file.text).split("\n").forEach((line, index) => {
        expect(line, `${file.path}:${index + 1}`).not.toMatch(BANNED);
      });
    }
  });

  it("never says blocked: monitor would have refused, and enforce refused", () => {
    // Field names (`blocked`, `wouldBlock`) are the CLI's; a quoted word is copy.
    const quoted = /(["'`])(?:(?!\1)[^\\]|\\.)*\1/g;
    for (const file of shipped) {
      for (const literal of withoutComments(file.text).match(quoted) ?? []) {
        expect(literal.replace(/\$\{[^}]*\}/g, ""), file.path).not.toMatch(/\bblocked\b/i);
      }
    }
  });
});

/** The only sentences that may name the paid edition, and the attribution words. */
const PERMITTED = [GENERIC_LINE, TOUR_UPGRADE_LINE, INSTALLED_LINE.lead, WITHHELD_WORDS.linux];
const ATTRIBUTION = /Active Defence on (?:this|its|the) host/g;

describe("(b) the paid edition is named only in the permitted sentences", () => {
  it("holds every line of every Community source, comments included", () => {
    let named = 0;
    for (const file of shipped) {
      file.text.split("\n").forEach((line, index) => {
        if (!line.includes("Active Defence")) return;
        named += 1;
        let rest = line;
        for (const sentence of PERMITTED) rest = rest.split(sentence).join("");
        rest = rest.replace(ATTRIBUTION, "");
        expect(rest, `${file.path}:${index + 1} names the paid edition outside the permitted sentences`).not.toContain("Active Defence");
      });
    }
    // Anti-vacuous: the offer and the attribution words are still here.
    expect(named).toBeGreaterThan(5);
  });

  it("says the three offer sentences exactly, each about what the edition is for", () => {
    expect(GENERIC_LINE).toBe("Active Defence adds host-level protection for Linux servers.");
    expect(TOUR_UPGRADE_LINE).toBe(
      "Community screens what your AI agents try to run. Active Defence, the paid edition, adds host-level protection for Linux servers.",
    );
    expect(INSTALLED_LINE.lead).toBe("Active Defence is installed on this host.");
  });
});

describe("(c) no product name for a guard or a gate, and no kernel", () => {
  it("holds every Community source, comments included", () => {
    for (const file of shipped) {
      file.text.split("\n").forEach((line, index) => {
        expect(line, `${file.path}:${index + 1}`).not.toMatch(/\b[A-Z][A-Za-z]* (?:Guard|Gate)\b/);
        expect(line, `${file.path}:${index + 1}`).not.toMatch(/kernel/i);
      });
    }
  });
});

describe("(e) no em or en dash", () => {
  it("holds every Community file, tests included", () => {
    for (const file of files) expect(file.text, file.path).not.toMatch(DASHES);
  });
});

// (d) needs the pages rendered: every polled source answers at once, from the
// CLI's fixtures, the way `pages.render.test.tsx` renders them.
const answers = new Map<string, unknown>();

function lookupOf(key: string): string {
  if (key.startsWith("{")) return "decisions";
  if (key.startsWith("cmd:")) return `decision:${key}`;
  if (key.startsWith("reason-preview:")) return "reason-preview";
  return key;
}

function answered(key: string) {
  const data = answers.get(lookupOf(key));
  return data === undefined
    ? { loading: true, stale: false, refresh: () => undefined }
    : { data, loading: false, stale: false, refresh: () => undefined };
}

vi.mock("./poll", () => ({ usePolled: (_load: unknown, _delay: number, key = "") => answered(key) }));
vi.mock("./store", () => ({ useSource: (key: string) => answered(key) }));

const { CommunityOverview } = await import("./Overview");
const { CommunityDecisions } = await import("./Decisions");
const { CommunityProtection } = await import("./Protection");
const { CommunityAgents } = await import("./Agents");

const SCENARIO_AGENTS: Record<string, unknown> = import.meta.glob("../../tests/fixtures/community/scenarios/*/agents.json", { eager: true, import: "default" });
const SCENARIO_META: Record<string, DashboardMeta> = import.meta.glob("../../tests/fixtures/community/scenarios/*/meta.json", { eager: true, import: "default" });
const scenarioOf = (path: string) => path.split("/").at(-2) ?? path;

function seed(agents: unknown = agentsFixture) {
  answers.clear();
  const denies = page1.items.filter((item) => item.recommendation === "deny");
  answers.set("sessions-probe", { supported: true, value: readSessionsPage({ ...sessionsFixture, items: sessionsFixture.items.slice(0, 1) }) });
  answers.set("sessions", { supported: true, value: readSessionsPage(sessionsFixture) });
  answers.set("reason-preview", readDecisionsPage({ ...page1, items: page1.items.slice(0, 5) }));
  answers.set("overview", overviewFixture);
  answers.set("overview-record", overviewFixture);
  answers.set("overview-denies", readDecisionsPage({ ...page1, items: denies.slice(0, 3), total: denies.length }));
  answers.set("overview-flagged", readDecisionsPage({ ...page1, items: page1.items.slice(0, 1) }));
  answers.set("decisions", readDecisionsPage(page1));
  answers.set("flagged-count", readDecisionsPage(page1));
  answers.set("agents", agents);
  answers.set("record-health", readRecordHealth({ recording: true }));
  answers.set("history", readHistory(historyFixture));
  answers.set("", readAttemptsPage(attemptsFixture));
  answers.set("protection", readProtection(protectionFixture));
  answers.set("suppress", { supported: true, value: readSuppressList(suppressFixture) });
  for (const [id, detail] of Object.entries(byId)) answers.set(`decision:${id}`, readDecisionDetail(detail));
}

function context(meta: DashboardMeta, search = ""): CommunityScreenContext {
  return {
    meta,
    metaStatus: "ready",
    navigate: () => undefined,
    search,
    bootstrap: { platform: { os: "macos", architecture: "arm64", enterprise_candidate: false, reason_code: null } } as never,
  };
}

type Node = { tag: string; attributes: string; children: Node[]; text: string; parent?: Node };

/** The rendered markup as a tree: enough of HTML for what React's static renderer writes. */
function tree(html: string): Node {
  const root: Node = { tag: "#root", attributes: "", children: [], text: "" };
  const VOID = new Set(["area", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
  let current = root;
  for (const token of html.match(/<[^>]+>|[^<]+/g) ?? []) {
    if (token.startsWith("</")) {
      current = current.parent ?? root;
    } else if (token.startsWith("<")) {
      const [, tag = "", attributes = ""] = /^<([a-zA-Z0-9-]+)([\s\S]*?)\/?>$/.exec(token) ?? [];
      const node: Node = { tag, attributes, children: [], text: "", parent: current };
      current.children.push(node);
      if (!VOID.has(tag) && !token.endsWith("/>")) current = node;
    } else {
      current.children.push({ tag: "#text", attributes: "", children: [], text: token, parent: current });
    }
  }
  return root;
}

const ENTITIES: Record<string, string> = { "&#x27;": "'", "&quot;": '"', "&lt;": "<", "&gt;": ">", "&amp;": "&" };
function textOf(node: Node): string {
  if (node.tag === "#text") return node.text.replace(/&#x27;|&quot;|&lt;|&gt;|&amp;/g, (entity) => ENTITIES[entity]);
  return node.children.map(textOf).join("");
}
function all(node: Node, match: (candidate: Node) => boolean, found: Node[] = []): Node[] {
  if (match(node)) found.push(node);
  for (const child of node.children) all(child, match, found);
  return found;
}
const has = (node: Node, attribute: string) => new RegExp(`\\s${attribute}(=|\\s|$)`).test(node.attributes);

/**
 * The step a command belongs to: the action block or getting-started list
 * it sits in, when it sits in one, and its own step box otherwise. Its
 * restart words are said inside that, beside the command.
 */
function stepOf(command: Node): Node | undefined {
  let step: Node | undefined;
  for (let node = command.parent; node !== undefined; node = node.parent) {
    if (has(node, "data-verdict-action") || has(node, "data-get-started")) return node;
    if (step === undefined && has(node, "data-step")) step = node;
  }
  return step;
}

/** Each config-changing command on the page, and whether a restart note is beside it. */
function configSteps(html: string): { command: string; restart: boolean }[] {
  return all(tree(html), (node) => has(node, "data-command"))
    .map((node) => ({ node, command: textOf(node).trim() }))
    .filter(({ command }) => changesAgentConfig(command))
    .map(({ node, command }) => {
      const step = stepOf(node);
      return { command, restart: step !== undefined && all(step, (candidate) => has(candidate, "data-restart")).length > 0 };
    });
}

describe("(d) every step that changes an agent's config says how to restart it", () => {
  beforeEach(() => seed());

  const render = (element: ReactElement) => renderToStaticMarkup(element);
  const meta = baseMeta as DashboardMeta;

  it("on the Overview, in every scenario the fixtures hold", () => {
    let seen = 0;
    const scenarios = Object.entries(SCENARIO_AGENTS).map(([path, agents]) => {
      const name = scenarioOf(path);
      const own = Object.entries(SCENARIO_META).find(([metaPath]) => scenarioOf(metaPath) === name)?.[1];
      return { name, agents, meta: own ?? meta };
    });
    for (const scenario of [{ name: "base", agents: agentsFixture as unknown, meta }, ...scenarios]) {
      seed(scenario.agents);
      for (const step of configSteps(render(createElement(CommunityOverview, { context: context(scenario.meta) })))) {
        seen += 1;
        expect(step.restart, `${scenario.name}: ${step.command}`).toBe(true);
      }
    }
    expect(seen, "anti-vacuous: some scenario offers a config-changing step").toBeGreaterThan(2);
  });

  it("on Protection and Agents", () => {
    const steps = [
      ...configSteps(render(createElement(CommunityProtection, { context: context(meta) }))),
      ...configSteps(render(createElement(CommunityAgents, { context: context(meta, "?view=agents") } as never))),
    ];
    expect(steps.length).toBeGreaterThan(1);
    for (const step of steps) expect(step.restart, step.command).toBe(true);
  });

  it("on every decision the fixtures hold", () => {
    for (const id of Object.keys(byId)) {
      const html = render(createElement(CommunityDecisions, { context: context(meta, `?view=activity&decision=${encodeURIComponent(id)}`) }));
      for (const step of configSteps(html)) expect(step.restart, `${id}: ${step.command}`).toBe(true);
    }
  });
});
