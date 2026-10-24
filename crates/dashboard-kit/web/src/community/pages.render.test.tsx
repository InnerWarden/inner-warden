import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import type { CommunityScreenContext } from "../App";
import type { AgentsResponse, DashboardMeta, TokenIntelligenceResponse } from "../api";
import { MachineIntelligenceSeed } from "../components/MachineIntelligence";
import { setTechnicalDetail } from "../components/TechnicalDetail";
// Every fixture below was written by the CLI's own fixture writer.
import overviewFixture from "../../tests/fixtures/community/overview.json";
import page1 from "../../tests/fixtures/community/decisions-page-1.json";
import byId from "../../tests/fixtures/community/decisions-by-id.json";
import historyFixture from "../../tests/fixtures/community/history.json";
import attemptsFixture from "../../tests/fixtures/community/history-attempts.json";
import protectionFixture from "../../tests/fixtures/community/protection.json";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import tokensFixture from "../../tests/fixtures/community/token-intelligence.json";
import sessionsFixture from "../../tests/fixtures/community/sessions.json";
import suppressFixture from "../../tests/fixtures/community/suppress.json";
import { readAttemptsPage, readDecisionDetail, readDecisionsPage, readHistory, readProtection, readRecordHealth, readSessionsPage, readSuppressList } from "./api";
import { ENFORCE_MEANS, MONITOR_MEANS } from "./words";

/**
 * The Community pages, RENDERED from the CLI's fixtures, with each polled
 * source answered at once. What is asserted is what a reader sees: the
 * words, the order, and the colours (by their one job each).
 */
const answers = new Map<string, unknown>();
const failing = new Set<string>();

/** A failing source's error, when it is not the plain "unreadable". */
const errors = new Map<string, Error>();

function lookupOf(key: string): string {
  if (key.startsWith("{")) return key.includes("reasonNot") ? "decisions-hidden" : "decisions";
  if (key.startsWith("cmd:")) return `decision:${key}`;
  if (key.startsWith("reason-preview:")) return "reason-preview";
  return key;
}

function answered(key: string) {
  const lookup = lookupOf(key);
  if (failing.has(lookup)) return { error: errors.get(lookup) ?? new Error("unreadable"), loading: false, stale: false, refresh: () => undefined };
  const data = answers.get(lookup);
  return data === undefined
    ? { loading: true, stale: false, refresh: () => undefined }
    : { data, loading: false, stale: false, refresh: () => undefined };
}

vi.mock("./poll", () => ({
  usePolled: (_load: unknown, _delay: number, key = "") => answered(key),
}));

// The shared sources answer from the same table, by their key.
vi.mock("./store", () => ({
  useSource: (key: string) => answered(key),
}));

const { CommunityOverview, footerItems, modeMeanings } = await import("./Overview");
const { messageStep } = await import("./DecisionDetail");
const { CommunityDecisions, decisionsParams, emptyListWords, filterCode, toParams } = await import("./Decisions");
const { CommunityProtection } = await import("./Protection");
const { CommunityAgents } = await import("./Agents");
const { CommunityTokens } = await import("./Tokens");
const { Notices } = await import("./Notices");
const { HeaderStatus } = await import("./HeaderStatus");
const { COMMUNITY_SHELL } = await import("./shell");

/** The fixture's denies, newest first: what `verdict=deny` answers. */
const DENIES = page1.items.filter((item) => item.recommendation === "deny");

const META: DashboardMeta = { version: "1.5.0", exposed: false, edition: "community", guardrail: { mode: "partial", guarded_agents: 3 } };

function context(search = "", meta: DashboardMeta = META, os = "macos"): CommunityScreenContext {
  return {
    meta,
    metaStatus: "ready",
    navigate: () => undefined,
    search,
    bootstrap: { platform: { os, architecture: "arm64", enterprise_candidate: false, reason_code: null } } as never,
  };
}

function seed() {
  answers.clear();
  failing.clear();
  errors.clear();
  answers.set("sessions-probe", { supported: true, value: readSessionsPage({ ...sessionsFixture, items: sessionsFixture.items.slice(0, 1) }) });
  answers.set("sessions", { supported: true, value: readSessionsPage(sessionsFixture) });
  answers.set("reason-preview", readDecisionsPage({ ...page1, items: page1.items.slice(0, 5) }));
  answers.set("overview", overviewFixture);
  answers.set("overview-record", overviewFixture);
  answers.set("recent-flagged", readDecisionsPage({ ...page1, items: page1.items.slice(0, 15) }));
  answers.set("overview-denies", readDecisionsPage({ ...page1, items: DENIES.slice(0, 3), total: DENIES.length }));
  answers.set("overview-flagged", readDecisionsPage({ ...page1, items: page1.items.slice(0, 1) }));
  answers.set("decisions", readDecisionsPage(page1));
  answers.set("flagged-count", readDecisionsPage(page1));
  answers.set("agents", agentsFixture);
  answers.set("tokens", tokensFixture);
  answers.set("record-health", readRecordHealth({ recording: true }));
  answers.set("history", readHistory(historyFixture));
  answers.set("", readAttemptsPage(attemptsFixture));
  answers.set("protection", readProtection(protectionFixture));
  for (const [id, detail] of Object.entries(byId)) answers.set(`decision:${id}`, readDecisionDetail(detail));
}

beforeEach(() => {
  seed();
  setTechnicalDetail(false);
  try {
    window.localStorage.clear();
  } catch {
    // No storage in this environment: every offer reads as not dismissed.
  }
});

afterEach(() => setTechnicalDetail(false));

/**
 * Rendered with the agent and token panels SEEDED from the fixtures: the
 * technical view's spec sheets draw their real content, not their loading
 * state, so the colour rules below are checked against what a reader sees.
 */
const render = (element: ReactElement) =>
  renderToStaticMarkup(
    <MachineIntelligenceSeed.Provider value={{ agents: agentsFixture as unknown as AgentsResponse, tokens: tokensFixture as unknown as TokenIntelligenceResponse }}>
      {element}
    </MachineIntelligenceSeed.Provider>,
  );

const ENTITIES: Record<string, string> = { "&#x27;": "'", "&quot;": '"', "&lt;": "<", "&gt;": ">", "&amp;": "&" };

/**
 * What a reader reads: the markup's text, tags gone, entities read back.
 * Tags are removed until none is left (one pass can leave a tag its own
 * removal put together), and entities are read back in ONE pass, so "&amp;lt;"
 * stays "&lt;" as the page shows it.
 */
function textOf(html: string): string {
  let text = html;
  let previous: string;
  do {
    previous = text;
    text = text.replace(/<[^<>]*>/g, "");
  } while (text !== previous);
  return text.replace(/&(?:#x27|quot|lt|gt|amp);/g, (entity) => ENTITIES[entity]);
}

/** Every command box's text, as a reader sees it (its words are spans). */
function commandBoxes(html: string): { text: string; copy: boolean; template: boolean }[] {
  const boxes: { text: string; copy: boolean; template: boolean }[] = [];
  for (const match of html.matchAll(/<code data-command="[^"]*"( data-template="[^"]*")?[^>]*>([\s\S]*?)<\/code>(\s*<button[^>]*aria-label="Copy command: )?/g)) {
    boxes.push({ text: textOf(match[2]), template: match[1] !== undefined, copy: match[3] !== undefined });
  }
  return boxes;
}

type Open = { tag: string; attrs: string };

/**
 * Every class token on the page with the attributes of every element around
 * it, from the markup alone. Enough HTML to walk React's own output: tags,
 * void elements and self-closing SVG.
 */
function classesWithAncestors(html: string): { classes: string[]; ancestors: string }[] {
  const out: { classes: string[]; ancestors: string }[] = [];
  const stack: Open[] = [];
  const voids = new Set(["area", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
  const tag = /<(\/?)([a-zA-Z][a-zA-Z0-9-]*)([^>]*?)(\/?)>/g;
  for (const match of html.matchAll(tag)) {
    const [, closing, name, attrs, selfClosing] = match;
    if (closing) {
      const at = stack.map((open) => open.tag).lastIndexOf(name);
      if (at !== -1) stack.length = at;
      continue;
    }
    const classMatch = /class="([^"]*)"/.exec(attrs);
    const ancestors = [...stack.map((open) => open.attrs), attrs].join(" ");
    if (classMatch) out.push({ classes: classMatch[1].split(/\s+/), ancestors });
    if (!selfClosing && !voids.has(name.toLowerCase())) stack.push({ tag: name, attrs });
  }
  return out;
}

/** The colour rule of every Community page (spec M5). */
function expectColourJobs(html: string) {
  for (const { classes, ancestors } of classesWithAncestors(html)) {
    for (const token of classes) {
      expect(token, "emerald is a confirmed read back; Community confirms nothing").not.toMatch(/emerald-/);
      if (/amber-/.test(token)) expect(ancestors, `${token} outside a needs-you element`).toMatch(/data-needs-you/);
      if (/rose-/.test(token)) {
        expect(ancestors, `${token} outside a bad outcome, a No, or an exposed dashboard`).toMatch(
          /data-outcome="unsafe_may_have_run"|data-mark="no"|data-exposed/,
        );
      }
    }
  }
}

function links(html: string): string[] {
  return [...html.matchAll(/href="(https:\/\/innerwarden\.com[^"]*)"/g)].map((match) => match[1]);
}

type FixtureItem = { outcome_key: string; command: string; command_whole: boolean; next: { command?: string; command_is_template?: boolean; view_action?: string }[] };
const BY_ID = byId as unknown as Record<string, { item: FixtureItem }>;
const OPEN_CASES = Object.keys(BY_ID).filter((id) => BY_ID[id].item.outcome_key !== "allowed");
const CASE_WOULD_REFUSE = page1.items.find((item) => item.command === "cat ~/.ssh/config")!.id;
const decisions = (search: string) => render(<CommunityDecisions context={context(search)} />);
const decisionHtml = (id: string) => decisions(`?view=activity&decision=${encodeURIComponent(id)}`);

describe("the colour jobs, on every Community page", () => {
  for (const technical of [false, true]) {
    it(`hold on every page in the ${technical ? "technical" : "plain"} view`, () => {
      setTechnicalDetail(technical);
      const pages = [
        render(<CommunityOverview context={context()} />),
        decisions("?view=activity"),
        decisions("?view=activity&lens=reason"),
        decisions("?view=activity&lens=session"),
        render(<CommunityProtection context={context()} />),
        render(<CommunityAgents />),
        render(<CommunityTokens />),
        decisions("?view=activity&lane=agent_messages&decision=" + attemptsFixture.items[0].id),
      ];
      for (const id of OPEN_CASES) pages.push(decisionHtml(id));
      for (const html of pages) expectColourJobs(html);
    });
  }

  /**
   * The technical views of Agents and Tokens are Community's own evidence
   * lists now, drawn in the same tokens: no badge colour of their own.
   */
  it("sees the technical view's evidence, and it is neutral", () => {
    setTechnicalDetail(true);
    for (const [html, marker] of [
      [render(<CommunityAgents />), "data-agent-evidence"],
      [render(<CommunityTokens />), "data-token-technical"],
    ] as const) {
      expect(html).toContain(marker);
      expectColourJobs(html);
      expect(html).not.toMatch(/emerald-|amber-|rose-/);
    }
  });

  /** FAILS ON REVERT: put the old emerald "Allowed" chip back and this fails. */
  it("would catch an emerald chip, an amber flag and a rose verdict", () => {
    expect(() => expectColourJobs('<span class="bg-emerald-50">Allowed</span>')).toThrow();
    expect(() => expectColourJobs('<span class="text-amber-900">Needs review</span>')).toThrow();
    expect(() => expectColourJobs('<span class="text-rose-800">Deny</span>')).toThrow();
    expect(() => expectColourJobs('<p data-needs-you=""><span class="text-amber-900">!</span></p>')).not.toThrow();
  });

  it("draws the notices in their own colours, in order", () => {
    const html = render(<Notices meta={{ ...META, exposed: true, update_pending: true, update_note: "A newer InnerWarden is installed. Restart the dashboard to use it." }} health={{ recording: false, sinceUnix: 1_790_690_000, lostActions: 37 }} />);
    expectColourJobs(html);
    expect(html.indexOf("open to the network")).toBeLessThan(html.indexOf("not recording"));
    expect(html.indexOf("not recording")).toBeLessThan(html.indexOf("A newer InnerWarden"));
    expect(html).toContain("37 actions were not recorded");
    expect(render(<Notices meta={META} health={{ recording: true }} />)).toBe("");
  });
});

describe("the header", () => {
  const chips = (html: string) => html.match(/data-pill=/g)?.length ?? 0;

  it("carries ONE chip, the most severe thing that is true, in both views", () => {
    const plain = render(<HeaderStatus meta={META} metaStatus="ready" />);
    expect(plain).toContain("Needs you");
    expect(plain).toContain('aria-live="polite"');
    expect(plain).not.toMatch(/class="[^"]*\bhidden\b/);
    const exposed = render(<HeaderStatus meta={{ ...META, exposed: true }} metaStatus="ready" />);
    expect(exposed).toContain("Open to network");
    expect(exposed).not.toContain("Needs you");
    expectColourJobs(exposed);
    answers.set("record-health", readRecordHealth({ recording: false }));
    const outage = render(<HeaderStatus meta={META} metaStatus="ready" />);
    expect(outage).toContain("Not recording");
    for (const technical of [false, true]) {
      setTechnicalDetail(technical);
      for (const html of [plain, exposed, outage, render(<HeaderStatus meta={{ ...META, exposed: true }} metaStatus="ready" />)]) expect(chips(html)).toBe(1);
      expect(render(<HeaderStatus meta={META} metaStatus="ready" />)).not.toContain("Local only");
    }
  });

  it("says Local only once, at the foot of the page, in the technical view", () => {
    const page = COMMUNITY_SHELL.screens.find((screen) => screen.route === "tokens")!;
    expect(render(<>{page.render(context())}</>)).not.toContain("Local only");
    setTechnicalDetail(true);
    expect(render(<>{page.render(context())}</>)).toContain("Local only");
  });
});

const overviewHtml = (search = "", meta: DashboardMeta = META) => render(<CommunityOverview context={context(search, meta)} />);

describe("the Overview", () => {

  /** FAILS ON REVERT: the band, the two numbers and the step are the page's first three things. */
  it("answers the three questions first: the band and its one step, then the two numbers", () => {
    const html = overviewHtml();
    const band = html.indexOf("data-verdict-row");
    const step = html.indexOf("data-step");
    const refused = html.indexOf('data-tour="overview-lanes"');
    const needs = html.indexOf('id="needs-a-look"');
    expect(band).toBeGreaterThan(-1);
    expect([band, step, refused, needs]).toEqual([band, step, refused, needs].slice().sort((a, b) => a - b));
    // The band is the page's heading, named for the page.
    expect(html).toMatch(/<h1[^>]*><span[^>]*>.*?<\/span><span class="min-w-0"><span class="sr-only">Overview: <\/span>Codex is only partly connected<\/span><\/h1>/);
    expect(html.match(/<h1/g)).toHaveLength(1);
    // Its one step is the CLI's, with the restart it needs.
    expect(commandBoxes(html.slice(band, refused)).map((box) => box.text)).toEqual(["innerwarden agents connect codex --monitor"]);
    expect(textOf(html)).toContain("If Codex is running, restart it after this step. Quit Codex and start it again.");
    expect(html).toContain('data-tour="overview-verdict"');
  });

  it("counts the last 7 days from the guard's log, and says today so far and where the count comes from", () => {
    const html = overviewHtml();
    const text = textOf(html);
    // 17 would have been refused in the last 7 UTC days; none refused.
    expect(text).toContain("0Refused before they ran");
    expect(text).toContain("17Would have been refused");
    expect(text).toContain("Today so far: 0 refused, 2 would have.");
    expect(text).toContain("From the guard's log, last 7 days (UTC). It keeps refusals since 30 Jul.");
    expect(html).toContain('aria-label="Last 14 days: 3 refused, 30 would have been refused"');
  });

  it("counts from the decision record, said as such, when the log sends no days", () => {
    const history = readHistory(historyFixture);
    answers.set("history", { ...history, refusals: { ...history.refusals, days: undefined } });
    const html = overviewHtml();
    const refused = textOf(html.slice(html.indexOf('id="refused"'), html.indexOf('id="needs-a-look"')));
    expect(refused).toContain("3Refused before they ran");
    expect(refused).toContain("6Would have been refused");
    expect(refused).toContain("From the decision record: newest 96 decisions, about 4 days.");
    expect(html.slice(html.indexOf('id="refused"'), html.indexOf('id="needs-a-look"'))).not.toContain("data-chart");
  });

  it("draws no count from a log it could not read", () => {
    answers.set("history", { ...readHistory(historyFixture), readable: false });
    const html = overviewHtml();
    const refused = html.slice(html.indexOf('id="refused"'), html.indexOf('id="needs-a-look"'));
    expect(textOf(refused)).toContain("Not read: the guard's log could not be read.");
    expect(refused).not.toContain("data-count");
    expect(refused).not.toContain("data-chart");
  });

  it("lists at most three denies and four reasons, with no Hide, and the way to all of them", () => {
    const html = overviewHtml();
    expect(html.match(/data-decision-row=/g)).toHaveLength(3);
    expect(html.match(/data-reason-row=/g)).toHaveLength(4);
    for (const deny of DENIES.slice(0, 3)) expect(html).toContain(`href="?view=activity&amp;decision=${encodeURIComponent(deny.id)}"`);
    expect(html).toContain(`href="?view=activity&amp;reason=${encodeURIComponent("rule:tmp_execution")}"`);
    expect(textOf(html)).toContain("See all 30 flagged in Decisions");
    expect(textOf(html)).not.toMatch(/\bHide\b/);
    expect(textOf(html)).toContain("From the decision record: newest 96 decisions, about 4 days.");
    // A row never shows a session id.
    expect(textOf(html)).not.toMatch(/[0-9a-f]{8}-demo-4000/);
  });

  it("says when the record is full and drops its oldest", () => {
    const page = readDecisionsPage(page1);
    answers.set("overview-flagged", { ...page, record: { ...page.record, capped: true } });
    expect(textOf(overviewHtml())).toContain("Older ones are dropped as new ones arrive.");
    answers.set("overview-flagged", page);
    expect(textOf(overviewHtml())).not.toContain("Older ones are dropped");
  });

  it("says a failed source in its own place and still draws the others", () => {
    failing.add("agents");
    failing.add("overview-flagged");
    const html = overviewHtml();
    expect(textOf(html)).toContain("Could not read whether your agents are connected");
    expect(textOf(html)).toContain("Nothing on this page is counted as zero.");
    expect(textOf(html)).toContain("Not read: the dashboard did not answer for the agents.");
    expect(html).toMatch(/role="alert"[^>]*>[\s\S]*The decision record could not be read/);
    // The guard's log answered, so its numbers are still drawn.
    expect(textOf(html)).toContain("17Would have been refused");
    expect(html).not.toContain("The local dashboard is unavailable");
    expect(textOf(html)).not.toContain("Nothing flagged");
  });

  it("never says nothing was flagged when rows could not be drawn", () => {
    answers.set("overview-flagged", { ...readDecisionsPage(page1), reasons: [] });
    const html = overviewHtml();
    expect(html).not.toContain("Nothing flagged");
    expect(textOf(html)).toContain("30 flagged could not be shown.");
  });

  it("says nothing was flagged only from the record's own count", () => {
    const page = readDecisionsPage(page1);
    answers.set("overview-flagged", { ...page, items: [], flaggedTotal: 0, total: 0, reasons: [] });
    expect(textOf(overviewHtml())).toMatch(/Nothing flagged in the record \(25 Sept, \d\d:34 to now\)\./);
  });

  it("makes no Active Defence offer and links out nowhere, installed or not", () => {
    for (const meta of [META, { ...META, active_defence_installed: true }]) {
      const html = overviewHtml("", meta);
      expect(links(html)).toEqual([]);
      expect(html).not.toContain("data-ad-state");
      expect(textOf(html)).not.toContain("Active Defence");
    }
  });

  it("says each control in the footer from what was read, and links each to where it is set", () => {
    const html = overviewHtml();
    const footer = textOf(html.slice(html.indexOf("data-overview-footer")));
    expect(footer).toContain("Record: recording.");
    expect(footer).toContain("Messages: 4 recorded.");
    expect(html).toContain('href="?view=posture#record"');
    expect(html).toContain('href="?view=activity&amp;lane=agent_messages"');
    expect(html).toContain('href="?view=tokens"');
  });

  it("keeps the CLI's step for an out-of-date message hook while messages are recorded", () => {
    const lanes = overviewFixture.lanes;
    answers.set("overview", {
      ...overviewFixture,
      lanes: {
        ...lanes,
        agent_messages: {
          ...lanes.agent_messages,
          next_step: { command: "innerwarden observe install", line: "The message hook on this machine is older than this version." },
        },
      },
    });
    const html = overviewHtml();
    const step = html.slice(html.indexOf("data-lane-step"));
    expect(commandBoxes(step).map((box) => box.text)).toContain("innerwarden observe install");
    expect(textOf(step)).toContain("older than this version");
    answers.set("overview", overviewFixture);
    expect(overviewHtml()).not.toContain("innerwarden observe install");
  });

  it("reads no token history, and draws no lane card, ring or tile", () => {
    const html = overviewHtml();
    expect(html).not.toContain("data-lane=");
    expect(html).not.toContain("on-machine-title");
    expect(html).not.toContain("Agents on this machine");
    expect(textOf(html)).not.toMatch(/\btokens\b/);
  });
});

describe("the first run", () => {
  const EMPTY = { ...readDecisionsPage(page1), items: [], total: 0, flaggedTotal: 0, byOutcome: {}, reasons: [], reasonsDistinct: 0, record: { decisions: 0, flagged: 0, checked: 0 } };
  const NOT_CONNECTED = {
    ...agentsFixture,
    agents: agentsFixture.agents.map((agent) => ({
      ...agent,
      guardrail: { ...agent.guardrail, mode: "not_configured" },
      next_step: { label: "To put the guard in front of it:", command: `innerwarden agents connect ${agent.id} --monitor`, line: "It starts in monitor mode." },
    })),
  };

  it("shows its first steps in place of Needs a look, with no offer and no link out", () => {
    answers.set("overview-flagged", EMPTY);
    answers.set("agents", NOT_CONNECTED);
    const html = overviewHtml();
    const steps = html.slice(html.indexOf("data-get-started"));
    expect(html.indexOf("data-get-started")).toBeGreaterThan(html.indexOf("data-verdict-row"));
    expect(html).not.toContain("Needs a look");
    expect(links(html)).toEqual([]);
    expect(html).not.toContain("data-offer");
    expect(commandBoxes(steps).map((box) => box.text)).toEqual(["innerwarden agents connect claude-code --monitor"]);
    // Step 2 is the restart itself: "now", never "after this step".
    expect(textOf(steps)).toContain("If Claude Code is running, restart it now.");
    expect(textOf(steps)).not.toContain("after this step");
    expect(textOf(steps)).toContain("Ask it to run any command. The decision shows here within seconds.");
    // The page they are reading is not a step.
    expect(commandBoxes(html).some((box) => box.text === "innerwarden dashboard")).toBe(false);
    // It never says nothing was flagged as if something had been checked.
    expect(textOf(html)).not.toContain("Nothing flagged");
  });

  it("asks for an agent before offering to connect one, when none is here", () => {
    answers.set("overview-flagged", EMPTY);
    answers.set("agents", { ...agentsFixture, agents: [] });
    const html = overviewHtml();
    expect(textOf(html)).toContain("Install a supported agent (Claude Code, Codex, Cursor, Gemini CLI), then connect it");
    expect(commandBoxes(html).some((box) => box.text.includes("agents connect"))).toBe(false);
  });

  it("is not onboarding again once an agent is connected", () => {
    answers.set("overview-flagged", EMPTY);
    const html = overviewHtml();
    expect(html).not.toContain("data-get-started");
    expect(textOf(html)).toContain("Nothing recorded yet. Ask your agent to run any command.");
  });
});

describe("Decisions", () => {
  it("counts the flagged decisions, splits them by outcome, and lists the newest first", () => {
    const html = decisions("?view=activity");
    const text = textOf(html);
    expect(html).toMatch(/<h1 id="decisions-title"[^>]*>Decisions<\/h1>/);
    expect(text).toContain("Every command or tool call the guard flagged, from the decision record.");
    expect(text).toContain("Newest 96 decisions, about 4 days.");
    const bar = textOf(html.slice(html.indexOf("data-outcome-bar"), html.indexOf("data-count-line")));
    // The outcome bar is the key to the marks: no second legend repeats it.
    expect(html).not.toContain("data-legend");
    expect(html).toMatch(/data-outcome-bar="true" data-tour="legend"/);
    expect(bar).toContain("Refused before it ran3");
    expect(bar).toContain("Would have been refused6");
    expect(bar).toContain("Judged unsafe, and it ran1");
    expect(bar).toContain("Flagged, and it ran20");
    expect(text).toContain(`25 rows on this page of ${page1.total}`);
    expect(text).toContain("more in a row, flagged for the same reason");
    // The agent's own tab says its count too, the same figure.
    expect(text).toMatch(new RegExp(`What your AI agent did${page1.flagged_total}`));
    // The list flows with the page; the detail is the sticky one.
    expect(html).toContain("lg:sticky");
    expect(html).not.toContain("lg:overscroll-contain");
  });

  it("never prints a rule id where a reason's words go", () => {
    const text = textOf(decisions("?view=activity&lens=reason"));
    expect(text).not.toMatch(/\[ATR-/);
    expect(text).toContain("high-risk tool invocation without human");
  });

  it("lists the reasons by the outcome most of them reached, with Hide, and the rarer ones one press away", () => {
    const html = decisions("?view=activity&lens=reason");
    expect(html.match(/data-reason-group=/g)).toHaveLength(8);
    expect(textOf(html)).toContain("And 2 more reasons");
    expect(textOf(html)).toContain("2 rarer reasons are not listed here.");
    expect(html).toMatch(/aria-label="Hide world-writable folder from the newest list"/);
    expect(html).toContain('aria-selected="true"');
    expect(html).toMatch(/id="lens-tab-reason"[^>]*aria-selected="true"/);
  });

  it("lists the sessions with decisions in the record, each opening its own list", () => {
    const html = decisions("?view=activity&lens=session");
    expect(html.match(/data-session-row=/g)).toHaveLength(sessionsFixture.items.length);
    expect(html).toContain(`href="?view=activity&amp;session=${encodeURIComponent(sessionsFixture.items[0].id)}"`);
    expect(textOf(html)).toContain("Sessions with decisions still in the record.");
  });

  it("offers the session lens only where this InnerWarden lists sessions", () => {
    expect(decisions("?view=activity")).toContain('data-lens="session"');
    answers.set("sessions-probe", { supported: false });
    const html = decisions("?view=activity&lens=session");
    expect(html).not.toContain('data-lens="session"');
    // An address that asked for it lands on the newest list.
    expect(html).toMatch(/id="lens-tab-newest"[^>]*aria-selected="true"/);
  });

  /**
   * A rule's quoted words are code, never stray backticks ("path: `.ssh/`."),
   * and a short code word stays whole on a phone ("my-" / "app" before).
   */
  it("prints a rule's quoted words as code, kept whole", () => {
    const credential = page1.items.find((item) => item.concern === "credential_read")!;
    const detail = decisionHtml(credential.id);
    const story = detail.slice(detail.indexOf('data-part="happened"'), detail.indexOf('data-part="did"'));
    expect(textOf(story)).not.toContain("`");
    const codes = [...story.matchAll(/<code data-segment-code="" class="([^"]*)">([^<]*)<\/code>/g)];
    expect(codes.map((match) => match[2])).toContain("my-app");
    for (const [, classes, text] of codes) {
      expect(classes, text).toContain(text.length > 28 ? "[overflow-wrap:anywhere]" : "whitespace-nowrap");
    }
    expect(codes.some(([, , text]) => text.startsWith("."))).toBe(true);
  });

  it("shows every decision's parts, in order, with no offer and no link out", () => {
    for (const id of OPEN_CASES) {
      const html = decisionHtml(id);
      const detail = html.slice(html.indexOf('aria-labelledby="decision-title"'));
      const parts = ['data-part="happened"', 'data-part="did"', 'data-part="next"'].map((part) => detail.indexOf(part));
      expect(parts.every((at) => at > 0), id).toBe(true);
      expect(parts, id).toEqual([...parts].sort((a, b) => a - b));
      expect(detail).toContain("data-not-checked-afterwards");
      expect(links(html), id).toEqual([]);
      expect(html, id).not.toContain("data-offer");
      expect(html, id).not.toContain("data-ad-state");
    }
  });

  it("says what InnerWarden did in three steps, and that nothing was checked afterwards", () => {
    const html = decisionHtml(CASE_WOULD_REFUSE);
    expect([...html.matchAll(/data-stage="([a-z]+)" data-mark="([a-z_]+)"/g)].map((match) => [match[1], match[2]])).toEqual([
      ["seen", "done"],
      ["decided", "done"],
      ["refused", "not_applicable"],
    ]);
    const text = textOf(html);
    expect(text).toContain("Not refused");
    expect(text).toContain("Monitor records and does not refuse");
    expect(text).toContain("Deny, by InnerWarden's rules");
    expect(text).toContain("Not checked afterwards: Community does not look at what a command did after it ran.");
    expect(text).toContain("Decided in monitor");
    // The heading is what the guard did, as the CLI says it.
    expect(html).toMatch(/<h2 id="decision-title"[^>]*>The rules said deny\./);
  });

  it("follows a step that changes an agent's config with that agent's restart words", () => {
    const id = Object.keys(BY_ID).find((key) => BY_ID[key].item.next.some((step) => step.command === "innerwarden enforce"))!;
    const html = decisionHtml(id);
    const step = html.slice(html.lastIndexOf("<div data-step", html.indexOf(">innerwarden</span>")));
    expect(textOf(step)).toMatch(/If (Claude Code|your agent) is running, restart it after this step\./);
    expect(textOf(step)).toContain("An agent reads its hook or MCP config only when it starts.");
    // An allow changes no agent config, and carries no restart.
    const allow = decisionHtml(page1.items.find((item) => item.command === "bash /tmp/build-cache/run.sh --clean")!.id);
    expect(allow).not.toContain("data-restart");
  });

  it("prints the CLI's commands exactly as sent", () => {
    const would = page1.items.find((item) => item.outcome_key === "would_have_refused")!;
    const boxes = commandBoxes(decisionHtml(would.id)).map((box) => box.text);
    for (const step of would.next) {
      if ("command" in step && step.command !== undefined) expect(boxes).toContain(step.command);
    }
  });

  /**
   * FAILS ON REVERT: a template (`innerwarden allow "<pattern>"`) and a
   * command shortened or shown written out each had a Copy button, and
   * pasted as they are they allow the literal `<pattern>` or run something
   * other than what ran.
   */
  it("offers Copy only for a command that works as it is", () => {
    let templates = 0;
    let notWhole = 0;
    for (const id of OPEN_CASES) {
      const item = BY_ID[id].item;
      for (const box of commandBoxes(decisionHtml(id))) {
        if (box.template || /<[^<>]+>/.test(box.text)) {
          templates += 1;
          expect(box.copy, `${id}: ${box.text}`).toBe(false);
        }
        if (box.text === item.command && !item.command_whole) {
          notWhole += 1;
          expect(box.copy, `${id}: ${box.text}`).toBe(false);
        }
      }
    }
    // Anti-vacuous: the fixtures hold both kinds.
    expect(templates).toBeGreaterThan(0);
    expect(notWhole).toBeGreaterThan(0);
  });

  it("says why a shortened or revealed command has nothing to copy", () => {
    const revealed = Object.keys(BY_ID).find((id) => BY_ID[id].item.command.includes("\\u{202E}"))!;
    const html = decisionHtml(revealed);
    expect(html).toContain("Contains hidden characters");
    expect(html).toContain("Shown with its hidden characters written out, so there is nothing whole to copy.");
  });

  it("offers to hide a per-session scratch script's reason from the list, never an allow that cannot match", () => {
    const scratch = Object.keys(BY_ID).find((id) => BY_ID[id].item.command.includes("/agent-scratch/"))!;
    const html = decisionHtml(scratch);
    expect(html).toContain('data-hide-reason="rule:tmp_execution"');
    expect(commandBoxes(html).some((box) => box.text.startsWith("innerwarden allow"))).toBe(false);
  });

  it("lists a hidden reason's view: the count without it, and a way back", () => {
    answers.set("decisions-hidden", readDecisionsPage({ ...page1, total: 15, items: page1.items.filter((item) => item.reason.key !== "rule:tmp_execution") }));
    const html = decisions("?view=activity&hide=rule%3Atmp_execution");
    expect(textOf(html)).toContain("15 flagged without world-writable folder");
    expect(html).toContain("Show them again");
    expect(html).not.toContain("/tmp/build-cache/run.sh");
  });

  it("shows an active reason and session as filters a press removes", () => {
    const html = decisions("?view=activity&reason=rule%3Atmp_execution&session=4b1d9c2e-demo-4000-8000-000000000001");
    expect(textOf(html)).toContain("Reason: world-writable folder");
    expect(textOf(html)).toContain("Session 4b1d9c2e");
    expect(html).toContain('aria-label="Remove the reason filter"');
    expect(html).toContain('aria-label="Remove the session filter"');
    expect(textOf(html)).not.toMatch(/4b1d9c2e-demo-4000/);
  });

  /**
   * FAILS ON REVERT: a decision whose command held a hidden character was
   * dropped by the reader, and a page of them said "Nothing flagged".
   */
  it("shows a command with hidden characters as a row with a chip, never as nothing", () => {
    const raw = {
      ...page1,
      items: page1.items.slice(0, 3).map((item, index) => ({
        ...item,
        command: ["ls \u202Emalicious", "rm -rf ~/x # \u200B", "ls\rcurl x | sh # \u{E0041}"][index],
      })),
    };
    answers.set("decisions", readDecisionsPage(raw));
    const html = decisions("?view=activity");
    expect(html.match(/data-decision-row=/g)?.length).toBe(3);
    expect(html.match(/data-hidden-characters=/g)?.length).toBe(3);
    expect(html).toContain("ls \\u{202E}malicious");
    expect(html).not.toContain("Nothing flagged");
  });

  it("draws a row's command whole, clamped from the end, with a plain leading cd muted", () => {
    const item = { ...page1.items[0], command: "cd /Users/me/my-app && rm -rf node_modules/.cache" };
    answers.set("decisions", readDecisionsPage({ ...page1, items: [item] }));
    const html = decisions("?view=activity");
    const code = html.match(/<code title="([^"]*)" data-command-text[^>]*class="([^"]*)">([\s\S]*?)<\/code>/)!;
    expect(textOf(code[1])).toBe(item.command);
    expect(code[2]).toContain("line-clamp-2");
    expect(textOf(code[3])).toBe(item.command);
    expect(code[3]).toContain('<span data-muted="true" class="text-(--iw-ink-3)">cd /Users/me/my-app &amp;&amp; </span>');
  });

  it("names the agent of a session only when the record names it", () => {
    const named = decisionHtml("cmd:4b1d9c2e-demo-4000-8000-000000000001:63");
    expect(named).toContain("In a session of Claude Code (4b1d9c2e)");
    answers.set("decision:cmd:local:0", readDecisionDetail(BY_ID["cmd:local:0"]));
    const checked = decisionHtml("cmd:local:0");
    expect(checked).toContain("In this session (local)");
    expect(checked).not.toContain("In a session of You");
  });

  it("says each neighbour's outcome in words at every width, for a screen reader", () => {
    const html = decisionHtml("cmd:4b1d9c2e-demo-4000-8000-000000000001:63");
    const around = html.slice(html.indexOf('id="around-title"'));
    const rows = around.match(/data-outcome-words="[a-z_]+"[^>]*class="([^"]*)"/g) ?? [];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row).toContain("sr-only");
      expect(row).toContain("sm:not-sr-only");
      expect(row).not.toMatch(/\bhidden\b/);
    }
  });

  it("offers Back to decisions on a phone, above the open decision", () => {
    const html = decisionHtml(CASE_WOULD_REFUSE);
    expect(html.indexOf("Back to decisions")).toBeGreaterThan(-1);
    expect(html.indexOf("Back to decisions")).toBeLessThan(html.indexOf('aria-labelledby="decision-title"'));
    expect(html).toMatch(/class="[^"]*lg:hidden[^"]*"[^>]*>.*Back to decisions/);
    expect(decisions("?view=activity")).not.toContain("Back to decisions");
  });

  it("says a decision the record dropped is gone, and why", () => {
    answers.set("decision:cmd:gone:1", "decision_not_in_record");
    const html = decisions("?view=activity&decision=cmd%3Agone%3A1");
    expect(html).toContain("This decision is no longer in the record");
    expect(html).toContain("InnerWarden keeps the newest decisions, and this one has been dropped.");
  });

  it("says a list that could not be read, never that nothing was flagged", () => {
    failing.add("decisions");
    const html = decisions("?view=activity");
    expect(html).toMatch(/role="alert"[^>]*>[\s\S]*The decision record could not be read/);
    expect(html).toContain("Try again");
    expect(html).not.toContain("Nothing flagged");
  });

  it("says a filter the server would not take, by its own code", () => {
    failing.add("decisions");
    errors.set("decisions", new Error("outcome_invalid"));
    const text = textOf(decisions("?view=activity&outcome=flagged_ran"));
    expect(text).toContain("That filter is not valid here (outcome_invalid).");
    expect(text).toContain("Clear filters");
    expect(filterCode(new Error("graph_unreadable"))).toBeUndefined();
    expect(filterCode("outcome_invalid")).toBeUndefined();
  });

  it("says the empty record and a record with nothing flagged apart, from the record's own counts", () => {
    const page = readDecisionsPage(page1);
    expect(emptyListWords({ ...page, flaggedTotal: 0, total: 0, record: { decisions: 0, flagged: 0, checked: 0 } }, false))
      .toBe("Nothing recorded yet. Connect an agent and ask it to run something.");
    expect(emptyListWords({ ...page, flaggedTotal: 0, total: 0 }, false)).toMatch(/^Nothing flagged in the record \(25 Sept, \d\d:34 to now\)\.$/);
    expect(emptyListWords({ ...page, total: 0 }, true)).toBe("No decision matches these filters.");
    expect(emptyListWords(page, false)).toBe("30 flagged could not be shown.");
  });

  it("reads the address back the way it writes it, and never writes the default lens", () => {
    const search = "?view=activity&lens=reason&outcome=flagged_ran&hide=rule%3Atmp_execution&q=curl";
    const state = decisionsParams(search);
    expect(state).toMatchObject({ lane: "agent_actions", lens: "reason", query: { outcome: "flagged_ran", reasonNot: "rule:tmp_execution", q: "curl" } });
    expect(toParams(state)).toEqual({ lens: "reason", outcome: "flagged_ran", hide: "rule:tmp_execution", q: "curl" });
    expect(toParams(decisionsParams("?view=activity&lens=newest"))).toEqual({});
    expect(decisionsParams("?view=activity&lens=nonsense").lens).toBe("newest");
    expect(decisionsParams("?view=activity&outcome=allowed&decision=x").query.outcome).toBe("allowed");
    expect(decisionsParams("?view=activity&outcome=bogus").query.outcome).toBeUndefined();
  });

  it("offers the messages tab, and no attacks or Everything tab", () => {
    const html = decisions("?view=activity");
    expect(html).toContain('data-lane="agent_messages"');
    expect(html).not.toContain('data-lane="server_attacks"');
    expect(html).not.toContain('data-lane="everything"');
  });

  it("offers the messages tab only where messages can be or were recorded", () => {
    const history = readHistory(historyFixture);
    answers.set("history", { ...history, messages: { ...history.messages, recorded: 0 } });
    answers.set("protection", { ...readProtection(protectionFixture), observe: { installed: false, available: false } });
    expect(decisions("?view=activity")).not.toContain('data-lane="agent_messages"');
    answers.set("protection", { ...readProtection(protectionFixture), observe: { installed: false, available: true } });
    expect(decisions("?view=activity")).toContain('data-lane="agent_messages"');
  });
});

describe("a message someone sent the agent", () => {
  const first = attemptsFixture.items[0];

  it("gives a real Community step, and no offer", () => {
    const html = decisions(`?view=activity&lane=agent_messages&decision=${first.id}`);
    const text = textOf(html);
    expect(text).toContain("If your agent had obeyed, the guard would have screened what it ran.");
    expect(commandBoxes(html).map((box) => box.text)).toContain("innerwarden enforce");
    // `innerwarden enforce` switches every connected agent: each one's restart, in its own words.
    for (const line of [
      "If Claude Code is running, restart it after this step. In Claude Code, type /exit, then run claude.",
      "If Codex is running, restart it after this step. Quit Codex and start it again.",
      "If Cursor is running, restart it after this step.",
      "If Gemini CLI is running, restart it after this step.",
    ]) expect(text).toContain(line);
    expect(text).not.toContain("If your agent is running");
    expect(html).not.toContain("data-offer");
    expect(links(html)).toEqual([]);
    expect(html).toContain("Contains hidden characters");
  });

  it("says there is nothing to do for a message InnerWarden stopped", () => {
    const stopped = { ...attemptsFixture, items: [{ ...first, outcome_key: "stopped_by_innerwarden" }] };
    answers.set("", readAttemptsPage(stopped));
    const html = decisions(`?view=activity&lane=agent_messages&decision=${first.id}`);
    expect(html).not.toContain("data-offer");
    expect(textOf(html)).toContain("Nothing to do: InnerWarden stopped it.");
  });

  it("says the lane's own words, and the count's span, never a zero it did not read", () => {
    const html = decisions("?view=activity&lane=agent_messages");
    expect(textOf(html)).toContain("Risky messages people sent your agent, from the guard's log");
    expect(textOf(html)).toContain(`${attemptsFixture.total} recorded since 30 Jul 2026.`);
    expect(html.match(/data-message-row=/g)?.length).toBe(attemptsFixture.items.length);
    answers.delete("");
    expect(textOf(decisions("?view=activity&lane=agent_messages"))).not.toContain("0 recorded");
  });
});

describe("Protection, Agents and Tokens", () => {
  const protectionHtml = (search = "", meta: DashboardMeta = META) => render(<CommunityProtection context={context(search, meta)} />);

  it("says the platform, the lead and one summary sentence, with no ring and no paid rows", () => {
    const html = protectionHtml();
    const text = textOf(html);
    expect(text).toContain("Protection on this Mac");
    expect(text).toContain("Community checks what your AI agents ask to run.");
    expect(text).toContain(
      "Screening: 1 agent refusing a deny, 1 in monitor, 1 needs you, 1 not yet seen working. Optional: AI Jail ready, alerts off, second opinion off, messages recording.",
    );
    // No ring: the only image on the page is the weekly chart.
    expect(html).not.toMatch(/Community controls on|of \d+ on/);
    expect(html.match(/role="img"/g)?.length).toBe(1);
    expect(html).not.toContain("Not in Community");
    expect(html).not.toContain("data-paid");
    // The paid edition: the one generic line at the foot, nothing else (copy.test.ts holds the words).
    expect(html.match(/data-ad-state=/g)?.length).toBe(1);
    expect(html).not.toContain("Checked after");
    expect(links(html)).toEqual(["https://innerwarden.com/docs/editions-and-guarantees"]);
    expect(html).toContain('data-tour="upgrade"');
    answers.set("protection", readProtection({ ...protectionFixture, platform: { os: "linux" } }));
    expect(protectionHtml()).toContain("Protection on this Linux machine");
    // Neither the controls nor the bootstrap read: no platform is guessed.
    failing.add("protection");
    expect(render(<CommunityProtection context={{ ...context(), bootstrap: undefined }} />)).toContain("Protection on this machine");
  });

  it("draws the mode box with both definitions, the switch, every agent's restart and the way back", () => {
    const html = protectionHtml();
    const box = html.slice(html.indexOf('id="mode"'), html.indexOf('id="screening"'));
    expect(box).toContain('data-tour="community-protection"');
    const text = textOf(box);
    expect(text).toContain("Mixed: Cursor and Gemini CLI are set to refuse a deny, Claude Code is in monitor.");
    expect(text).toContain("Monitor is a dry run: every command is checked and recorded, and none is stopped.");
    expect(text).toContain("Enforce: a deny is refused before it runs. A review is recorded and, by default, still runs.");
    expect(text.match(/Monitor is a dry run/g)?.length).toBe(1);
    expect(commandBoxes(box).map((b) => b.text)).toEqual(["innerwarden agents connect claude-code", "innerwarden dry-run"]);
    expect(text).toContain("If Claude Code is running, restart it after this step. In Claude Code, type /exit, then run claude.");
    expect(text).toContain("If Codex is running, restart it after this step. Quit Codex and start it again.");
  });

  it("lists one screening row per connected agent: how, what it judges, mode and seen kept apart, and its step", () => {
    const html = protectionHtml();
    const screening = html.slice(html.indexOf('id="screening"'), html.indexOf('id="record"'));
    expect(screening.match(/data-screening=/g)?.length).toBe(4);
    expect(screening).toContain('data-screening="gemini" data-control-state="unknown"');
    const text = textOf(screening);
    expect(text).toContain("2 of 3 local servers wrapped.");
    expect(text).toContain("1 remote server is not screened (Community wraps local servers only).");
    expect(text).toContain("Calls to its MCP servers. Its built-in tools are not screened by this edition.");
    // Gemini was screened before its settings changed and not since: never "Screened".
    const gemini = screening.slice(screening.indexOf('data-screening="gemini"'));
    expect(textOf(gemini)).toContain("Nothing since its settings changed on 27 Sept at 14:05");
    expect(gemini).not.toContain('data-seen="screened"');
    expect(text).not.toContain("Checked after");
    // Codex sends no judges line: not drawn in the plain view, "Not read" in the technical one.
    const codex = textOf(screening.slice(screening.indexOf('data-screening="codex"'), screening.indexOf('data-screening="cursor"')));
    expect(codex).not.toContain("Judges before it runs");
    setTechnicalDetail(true);
    const technical = protectionHtml();
    const codexTech = textOf(technical.slice(technical.indexOf('data-screening="codex"'), technical.indexOf('data-screening="cursor"')));
    expect(codexTech).toContain("Judges before it runsNot read");
  });

  it("says the record, its span and the guard's log by week, the week under way outlined, not dropped", () => {
    const html = protectionHtml();
    const record = textOf(html.slice(html.indexOf('id="record"'), html.indexOf('id="optional"')));
    expect(record).toMatch(/Recording\. The newest 96 decisions, from 25 Sept, \d\d:\d\d to now \(about \d+ \w+\)\./);
    expect(record).toContain("The guard's log keeps refusals and list changes since 30 Jul (10 weeks).");
    expect(record).toContain("this week so far");
    answers.set("history", readHistory({ ...historyFixture, readable: false }));
    expect(textOf(protectionHtml())).toContain("Not read: the guard's log could not be read.");
  });

  it("says each optional defence in words, a count for alerts, and a template the reader fills in", () => {
    const html = protectionHtml();
    const optional = html.slice(html.indexOf('id="optional"'), html.indexOf('id="exceptions"'));
    for (const id of ["jail", "alerts", "second-opinion", "messages"]) expect(optional).toContain(`id="${id}"`);
    const text = textOf(optional);
    expect(text).toContain("Ready: the checks a jail needs pass on this machine (sandbox-exec).");
    expect(text).toContain("Off: no alert channel is set up.");
    expect(text).toContain("Recording: 4 messages since 30 Jul.");
    const boxes = commandBoxes(optional);
    expect(boxes.find((box) => box.text === "innerwarden contain -- <command>")).toMatchObject({ template: true, copy: false });
    expect(boxes.find((box) => box.text === "innerwarden notify")?.copy).toBe(true);
    // An absent check reads not checked here yet, never ready.
    answers.set("protection", readProtection({ ...protectionFixture, jail: { available: true, backend: "sandbox-exec" } }));
    expect(textOf(protectionHtml())).toContain("Not checked here yet (sandbox-exec found).");
  });

  it("lists the exceptions when the CLI serves them, and the counts when it does not", () => {
    answers.set("suppress", { supported: true, value: readSuppressList(suppressFixture) });
    const html = protectionHtml();
    const exceptions = html.slice(html.indexOf('id="exceptions"'));
    const text = textOf(exceptions);
    expect(text).toContain("5 allow patterns, 1 muted rule, 1 muted category.");
    expect(text).toContain("Matches more than one command");
    expect(text).toContain("Contains a secret, hidden here.");
    expect(text).toContain("Ignored: matches every command.");
    expect(text).toContain("ATR-2026-030: cross-agent attack detection");
    expect(text).toContain("Adding to these lists needs a terminal: the CLI refuses an allow or mute that runs with no terminal, as an agent's shell does. Removing one does not.");
    expect(text).not.toContain("An agent that runs them is refused");
    expect(commandBoxes(exceptions).map((box) => box.text)).not.toContain("innerwarden allow --remove 'deploy-cli --token=[REDACTED]'");
    answers.set("suppress", { supported: false });
    const older = textOf(protectionHtml().slice(protectionHtml().indexOf('id="exceptions"')));
    expect(older).toContain("5 allow patterns, 1 muted rule, 1 muted category.");
    expect(older).toContain("This InnerWarden lists only the counts.");
  });

  it("gives each agent its card: judges, servers, seen, its own switch with the restart, and no link out", () => {
    const html = render(<CommunityAgents />);
    const text = textOf(html);
    expect(text).toContain("Automatic setup is on: a new agent joins in monitor, checked every 60 s.");
    expect(text.match(/Monitor is a dry run/g)?.length).toBe(1);
    expect(html).toContain('id="agent-claude-code"');
    expect(text).toContain("Judges before it runs: Shell commands, and file changes");
    expect(text).toContain("2 of 3 local servers wrapped.");
    expect(text).toContain("Last screened");
    expect(commandBoxes(html).map((box) => box.text)).toContain("innerwarden agents connect codex --monitor");
    expect(commandBoxes(html).map((box) => box.text)).toContain("innerwarden agents connect claude-code");
    expect(text).toMatch(/Its settings changed on 27 Sept at \d\d:\d\d and nothing has come through since\./);
    expect(text).toContain("If Gemini CLI is running, restart it after this step. Quit Gemini CLI and start it again.");
    expect(links(html)).toEqual([]);
    expect(html).not.toContain("data-offer");
  });

  it("says running as not read on macOS in the technical view, never not running", () => {
    answers.set("protection", readProtection(protectionFixture));
    setTechnicalDetail(true);
    const text = textOf(render(<CommunityAgents />));
    expect(text).toContain("Running: not read on macOS");
    expect(text).not.toMatch(/Running: no\b/);
    expect(text).not.toMatch(/not running/i);
    expect(text).toContain("Program on PATH: found");
  });

  it("leads tokens with what is not a cache read, never stacks overlapping counters, and links nowhere", () => {
    const html = render(<CommunityTokens />);
    const text = textOf(html);
    expect(html.match(/prompts and responses never reach this dashboard/g)?.length).toBe(1);
    expect(text).toContain("41 milliontokens, not counting cache reads");
    expect(text).toContain("plus 1.3 billion re-read from cache");
    expect(text).toContain("1.0 billion input, of which 959 million cached");
    expect(text).toContain("No local source for Cursor's tokens.");
    expect(text).not.toMatch(/Cursor[^.]*\b0 tokens/);
    const codex = html.slice(html.indexOf('data-token-agent="codex"'), html.indexOf('data-token-agent="cursor"'));
    expect(codex).not.toContain("data-part=");
    expect(links(html)).toEqual([]);
    expect(html).not.toContain("A sample, not the total");
  });

  it("says plainly that a capped scan read only the newest history", () => {
    const sampled = {
      ...tokensFixture,
      agents: tokensFixture.agents.map((agent) =>
        agent.agent_id === "claude" ? { ...agent, coverage: { complete: false, files_read: 40, files_found: 1879 } } : agent,
      ),
    };
    answers.set("tokens", sampled);
    const text = textOf(render(<CommunityTokens />));
    expect(text).toContain("Read 40 of 1,879 files: the newest history only.");
    setTechnicalDetail(true);
    expect(textOf(render(<CommunityTokens />))).toContain("Per-day totals are not recorded.");
  });
});

describe("review fixes, as a reader sees them", () => {
  const protectionHtml = () => render(<CommunityProtection context={context()} />);

  /** The band carries one fact: open to the network wins, so not recording is still said above it. */
  it("still says not recording on the Overview when the dashboard is also exposed", () => {
    const both = { meta: { ...META, exposed: true }, health: { recording: false, lostActions: 2 } };
    const overview = render(<Notices {...both} inBand />);
    expect(overview).toContain('data-notice="recording"');
    expect(overview).not.toContain("data-exposed");
    const onlyOutage = render(<Notices meta={META} health={{ recording: false }} inBand />);
    expect(onlyOutage).toBe("");
    const elsewhere = render(<Notices {...both} />);
    expect(elsewhere).toContain("data-exposed");
    expect(elsewhere).toContain('data-notice="recording"');
  });

  /** One fix on every page: the band's step, the same flag, and the way to the Overview. */
  it("gives the exposed banner the band's own step and a way to the Overview", () => {
    const text = textOf(render(<Notices meta={{ ...META, exposed: true }} />));
    expect(text).toContain("Stop the dashboard and start it again with innerwarden dashboard: without --expose it answers on this machine only.");
    expect(text).toContain("Open the Overview");
    expect(text).not.toContain("--bind");
  });

  /** T4: a screen that shows a mode says what monitor means, once, whatever row the band is on. */
  it("says what monitor means exactly once on every Overview that draws a mode pill", () => {
    const monitorAll = {
      ...agentsFixture,
      agents: agentsFixture.agents.map((agent) => ({ ...agent, guardrail: { ...agent.guardrail, mode: agent.guardrail.mode === "not_configured" ? "not_configured" : "monitor" } })),
    };
    for (const agents of [agentsFixture, monitorAll]) {
      answers.set("agents", agents);
      const text = textOf(overviewHtml());
      expect(text.split(MONITOR_MEANS).length - 1, JSON.stringify(agents.agents.map((agent) => agent.guardrail.mode))).toBe(1);
    }
    // The default fixture draws Enforce pills too, and the band does not say enforce.
    answers.set("agents", agentsFixture);
    expect(textOf(overviewHtml()).split(ENFORCE_MEANS).length - 1).toBe(1);
    expect(modeMeanings([], [])).toEqual([]);
  });

  /** Desk order is DOM order: Agents, then Refused, then Needs a look; the phone reorders by CSS only. */
  it("puts the Agents strip first in the DOM, as it is drawn at a desk", () => {
    const html = overviewHtml();
    const agents = html.indexOf('id="overview-agents"');
    const refused = html.indexOf('id="refused"');
    const needs = html.indexOf('id="needs-a-look"');
    expect(agents).toBeLessThan(refused);
    expect(refused).toBeLessThan(needs);
    expect(html).toMatch(/id="overview-agents"[^>]*class="[^"]*order-3 lg:order-none/);
    expect(html).toMatch(/id="refused"[^>]*class="[^"]*order-1 lg:order-none/);
  });

  /** T6: the two numbers say their span where they are read, and the chart says its own. */
  it("names the span of the two numbers and of the chart where they are read", () => {
    const refused = html(overviewHtml(), 'id="refused"', 'id="needs-a-look"');
    expect(textOf(refused)).toMatch(/Refused, or would have beenLast 7 days0Refused before they ran17Would have been refusedLast 14 days/);
  });

  it("says Messages: not read when the guard's log could not be read, never 0 recorded", () => {
    answers.set("history", { ...readHistory(historyFixture), readable: false });
    const footer = textOf(overviewHtml().slice(overviewHtml().indexOf("data-overview-footer")));
    expect(footer).toContain("Messages: not read.");
    expect(footer).not.toContain("Messages: 0 recorded.");
    expect(footerItems({ recording: true }, readProtection(protectionFixture), { ...readHistory(historyFixture), readable: false }).find((item) => item.key === "messages")?.words).toBe("Messages: not read.");
  });

  /** WCAG 1.4.1: a link is told apart by more than its place. */
  it("draws the footer's items as links: accent and underlined", () => {
    const footer = overviewHtml().slice(overviewHtml().indexOf("data-overview-footer"));
    for (const match of footer.matchAll(/<a href="[^"]*"[^>]*class="([^"]*)"/g)) {
      expect(match[1]).toContain("text-(--iw-accent)");
      expect(match[1]).toMatch(/(^| )underline( |$)/);
    }
  });

  /** A log that could not be read is not "no change". FAILS ON REVERT of the not-read line. */
  it("says the list changes were not counted when the guard's log could not be read", () => {
    answers.set("suppress", { supported: true, value: readSuppressList({ ...suppressFixture, changes: { count: null, since: null, last_at: null } }) });
    const exceptions = textOf(protectionHtml().slice(protectionHtml().indexOf('id="exceptions"')));
    expect(exceptions).toContain("Not read: the guard's log could not be read, so changes are not counted.");
    expect(exceptions).not.toContain("No change to these lists");
  });

  /** T7: a pattern cut short is said as such, with the terminal step to remove it. FAILS ON REVERT of the shortened chip. */
  it("marks a shortened allow pattern and names the terminal step to remove it", () => {
    const cut = `${"a".repeat(399)}…`;
    answers.set("suppress", {
      supported: true,
      value: readSuppressList({ ...suppressFixture, allow: [{ pattern: cut, redacted: false, hidden_characters: false, warning: null, shortened: true }] }),
    });
    const html = protectionHtml();
    const row = html.slice(html.indexOf('data-allow="shortened"'), html.indexOf("</li>", html.indexOf('data-allow="shortened"')));
    expect(row).toContain("data-shortened");
    expect(textOf(row)).toContain("Shortened here");
    expect(textOf(row)).toContain("Remove it from a terminal: innerwarden allow --list shows it.");
    expect(row).not.toContain("data-remove");
  });

  it("counts the list entries it could not show, never drops them silently", () => {
    answers.set("suppress", { supported: true, value: readSuppressList({ ...suppressFixture, mute_categories: [{ id: 7 }] }) });
    expect(textOf(protectionHtml())).toContain("1 entry could not be shown here.");
  });

  /** T5: `innerwarden enforce` switches every connected agent, so every one of them is restarted after it. */
  it("follows a decision's switch for every agent with every connected agent's restart", () => {
    const text = textOf(decisionHtml(CASE_WOULD_REFUSE));
    const next = text.slice(text.indexOf("What you can do"));
    for (const name of ["Claude Code", "Codex", "Cursor", "Gemini CLI"]) expect(next).toContain(`If ${name} is running, restart it after this step.`);
    expect(next).not.toContain("If your agent is running");
  });

  /** CJC-090 must not claim every action is intercepted: the step follows the mode that was read. */
  it("words a message's step by the mode read, and claims nothing when the mode is unknown", () => {
    expect(messageStep("answered", "enforce").text).toBe("Nothing to do here: a deny from your connected agents is refused before it runs.");
    expect(messageStep("declined_by_agent", "enforce").text).toContain("a deny from your connected agents is refused before it runs");
    expect(messageStep("answered", "not_configured")).toEqual({
      text: "No agent is connected to the guard, so nothing your agent runs is screened. To connect every agent found here, in monitor:",
      command: "innerwarden agents connect --all --monitor",
    });
    expect(messageStep("answered", "unknown")).toEqual({ text: "The mode could not be read, so this page claims none. To see it:", command: "innerwarden status" });
    for (const mode of ["enforce", "not_configured", "unknown", "monitor", "mixed", "partial"]) {
      expect(messageStep("answered", mode).text, mode).not.toMatch(/screens whatever|every action/);
    }
    const first = attemptsFixture.items[0];
    for (const [mode, words] of [
      ["enforce", "a deny from your connected agents is refused before it runs"],
      ["not_configured", "No agent is connected to the guard"],
      ["unknown", "The mode could not be read, so this page claims none."],
    ] as const) {
      const html = render(<CommunityDecisions context={context(`?view=activity&lane=agent_messages&decision=${first.id}`, { ...META, guardrail: { mode, guarded_agents: 0 } })} />);
      expect(textOf(html), mode).toContain(words);
    }
  });

  /** The ladder's bold label reads true on its own. */
  it("labels a monitor deny's third step Not refused, never Refused", () => {
    const html = decisionHtml(CASE_WOULD_REFUSE);
    const stage = html.slice(html.indexOf('data-stage="refused"'), html.indexOf("</li>", html.indexOf('data-stage="refused"')));
    expect(textOf(stage)).toContain("Not refused");
    expect(stage).not.toMatch(/<\/span>Refused<span/);
  });
});

function html(page: string, from: string, to: string): string {
  return page.slice(page.indexOf(from), page.indexOf(to));
}
