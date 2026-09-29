import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import type { CommunityScreenContext } from "../App";
import type { DashboardMeta } from "../api";
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

vi.mock("./poll", () => ({
  usePolled: (_load: unknown, _delay: number, key = "") => {
    const lookup = key.startsWith("{") ? "decisions" : key.startsWith("cmd:") ? `decision:${key}` : key;
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

const META: DashboardMeta = { version: "1.5.0", exposed: false, edition: "community", guardrail: { mode: "partial", guarded_agents: 3 } };

function context(search = "", meta: DashboardMeta = META): CommunityScreenContext {
  return {
    meta,
    metaStatus: "ready",
    navigate: () => undefined,
    search,
    bootstrap: { platform: { os: "macos", architecture: "arm64", enterprise_candidate: false, reason_code: null } } as never,
  };
}

function seed() {
  answers.clear();
  failing.clear();
  answers.set("overview", overviewFixture);
  answers.set("overview-record", overviewFixture);
  answers.set("recent-flagged", readDecisionsPage({ ...page1, items: page1.items.slice(0, 15) }));
  answers.set("decisions", readDecisionsPage(page1));
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

const render = (element: ReactElement) => renderToStaticMarkup(element);

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

const OPEN_CASES = Object.keys(byId).filter((id) => (byId as Record<string, { item: { outcome_key: string } }>)[id].item.outcome_key !== "allowed");

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
      for (const id of OPEN_CASES) pages.push(render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent(id)}`)} />));
      for (const html of pages) expectColourJobs(html);
    });
  }

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

  it("says what the guard does in the header at every width, and exposure in both views", () => {
    const plain = render(<HeaderStatus meta={META} metaStatus="ready" />);
    expect(plain).toContain("Partly connected");
    expect(plain).not.toMatch(/class="[^"]*\bhidden\b/);
    expect(plain).not.toContain("Local");
    const exposed = render(<HeaderStatus meta={{ ...META, exposed: true }} metaStatus="ready" />);
    expect(exposed).toContain("Open to the network");
    expectColourJobs(exposed);
    setTechnicalDetail(true);
    expect(render(<HeaderStatus meta={META} metaStatus="ready" />)).toContain("Local only");
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

  it("makes one offer, in the card Community cannot fill, and links out once", () => {
    const html = render(<CommunityOverview context={context()} />);
    expect(links(html)).toEqual(["https://innerwarden.com/pricing"]);
    const server = html.slice(html.indexOf('data-lane="server_attacks"'));
    expect(server).toContain('data-offer="server"');
    expect(server).toContain("Active Defence runs on Linux servers");
  });

  it("says a failed source in its own place and still draws the others", () => {
    failing.add("agents");
    failing.add("overview");
    const html = render(<CommunityOverview context={context()} />);
    expect(html).toContain("Agents did not answer");
    expect(html).toContain("The decision record could not be read");
    expect(html).toContain("tokens");
    expect(html).not.toContain("The local dashboard is unavailable");
  });

  it("lists the five newest flagged situations, a run of one reason folded, never a session id", () => {
    const html = render(<CommunityOverview context={context()} />);
    expect(html.match(/data-case-row=/g)?.length).toBe(5);
    // The six build-cache scripts in a row are ONE situation, not five rows.
    expect(html).toContain("5 more in a row, flagged for the same reason");
    expect(html).toContain("bash /tmp/build-cache/run.sh --clean");
    expect(html).not.toContain("bash /tmp/build-cache/step-1.sh");
    const text = html.replace(/<[^>]+>/g, " ");
    expect(text).not.toMatch(/[0-9a-f]{8}-demo-4000/);
  });

  it("claims installation, never protection, where Active Defence is installed", () => {
    const html = render(<CommunityOverview context={context("", { ...META, active_defence_installed: true })} />);
    expect(html).toContain('data-ad-state="installed"');
    expect(links(html)).toEqual([]);
    for (const word of [" armed", "enforcing", "protected"]) expect(html.toLowerCase()).not.toContain(word);
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
  });

  it("shows every case's three parts, in order, with what you can do", () => {
    for (const id of OPEN_CASES) {
      const html = render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent(id)}`)} />);
      const detail = html.slice(html.indexOf('aria-labelledby="case-title"'));
      const parts = ["What happened", "What InnerWarden did", "What you can do"].map((term) => detail.indexOf(`>${term}</dt>`));
      expect(parts.every((at) => at > 0), id).toBe(true);
      expect(parts, id).toEqual([...parts].sort((a, b) => a - b));
      expect(links(html).length, id).toBeLessThanOrEqual(1);
    }
  });

  it("prints the CLI's commands exactly as sent", () => {
    const would = page1.items.find((item) => item.outcome_key === "would_have_refused")!;
    const html = render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent(would.id)}`)} />);
    for (const step of would.next) {
      if ("command" in step && step.command !== undefined) expect(html).toContain(`>${step.command}</code>`);
    }
  });

  it("names Secret Read Guard only on a case that reached for a credential", () => {
    const credential = page1.items.find((item) => item.concern === "credential_read" && item.outcome_key === "would_have_refused")!;
    const other = page1.items.find((item) => item.concern === "other" && item.outcome_key === "flagged_ran")!;
    expect(render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent(credential.id)}`)} />)).toContain("Secret Read Guard");
    const html = render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent(other.id)}`)} />);
    expect(html).not.toContain("Secret Read Guard");
    expect(html).toContain("Execution Gate");
  });

  it("names the agent of a session only when the record names it", () => {
    const named = render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent("cmd:4b1d9c2e-demo-4000-8000-000000000001:63")}`)} />);
    expect(named).toContain("In a session of Claude Code (4b1d9c2e)");
    const checked = render(<CommunityCases context={context(`?view=activity&decision=${encodeURIComponent("cmd:local:0")}`)} />);
    expect(checked).toContain("In this session (local)");
    expect(checked).not.toContain("In a session of You");
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

  it("gives each agent its state and the CLI's command, with no link out", () => {
    const html = render(<CommunityAgents />);
    expect(html).toContain("Partly connected");
    expect(html).toContain(">innerwarden agents connect codex --monitor</code>");
    expect(html).toContain("Last screened a command");
    expect(links(html)).toEqual([]);
  });

  it("draws token use once per agent, with the provenance said once, and no link out", () => {
    const html = render(<CommunityTokens />);
    expect(html.match(/prompts and responses never reach this dashboard/g)?.length).toBe(1);
    expect(html).toContain("1,271,432,724");
    expect(html).toContain("Keeps no token history InnerWarden can read.");
    expect(links(html)).toEqual([]);
  });
});
