import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pinZone } from "../../test-support/zone";
// Written by the CLI's own fixture writer, not by hand.
import agentsFixture from "../../../tests/fixtures/community/agents.json";
import historyFixture from "../../../tests/fixtures/community/history.json";
import page1 from "../../../tests/fixtures/community/decisions-page-1.json";
import sessionsFixture from "../../../tests/fixtures/community/sessions.json";
import { readAgentsFacts, readDecisionsPage, readHistory, readSessionsPage, type Decision } from "../api";
import { overviewVerdict } from "../verdict";
import { MONITOR_MEANS } from "../words";
import { NotRead, StepBlock, VerdictBand, CountStat } from "./blocks";
import { DayBars, share, TokenBars, WeekBars } from "./charts";
import { HatchDefs, ModePill, OutcomeMark, StatusPill } from "./marks";
import { AgentStrip, DecisionRow, ReasonRow, SeenCell, SessionRow } from "./rows";

const NOW = Date.parse("2026-09-29T14:05:00Z");
let restoreZone: () => void;
beforeAll(() => {
  restoreZone = pinZone("UTC");
});
afterAll(() => restoreZone());

/** An en or an em dash, built at run time so this file carries neither. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);

const render = (element: React.ReactElement) => {
  const html = renderToStaticMarkup(element);
  expect(html).not.toMatch(DASHES);
  return html;
};

const facts = readAgentsFacts(agentsFixture);
const history = readHistory(historyFixture);
const page = readDecisionsPage(page1);

describe("the verdict band", () => {
  it("holds its place with a busy skeleton until the first answers land", () => {
    const html = render(<VerdictBand verdict={{ row: 0, tone: "unknown", lines: [] }} />);
    expect(html).toContain('aria-busy="true"');
    expect(html).toContain("min-h-[188px]");
  });

  it("draws one headline, what monitor means, one step with each restart, and the way back", () => {
    const monitorOnly = facts.agents.filter((agent) => agent.id === "claude-code");
    const verdict = overviewVerdict({ metaStatus: "ready", meta: {}, health: { recording: true }, agents: monitorOnly, agentsFailed: false, unnamed: {}, days: history.refusals.days, logReadable: true, now: NOW });
    const html = render(<VerdictBand verdict={verdict} />);
    expect(html).toContain('data-tone="watch"');
    expect(html).toContain("Your AI agent is connected. Monitor: nothing is refused.");
    expect(html).toContain(MONITOR_MEANS);
    expect(html).toContain('aria-label="Copy command: innerwarden enforce"');
    expect(html).toContain("If Claude Code is running, restart it after this step. In Claude Code, type /exit, then run claude.");
    expect(html).toContain("Back to monitor any time:");
    expect(html).toContain('aria-label="Copy command: innerwarden dry-run"');
  });

  it("shows a template step to fill in, never to copy", () => {
    const html = render(<StepBlock step={{ label: "To start one:", command: "innerwarden contain -- <command>", line: "Runs it in the jail." }} />);
    expect(html).toContain("data-template");
    expect(html).not.toContain("Copy command:");
  });
});

describe("what could not be read", () => {
  it("is dashed and in words, never a zero", () => {
    const html = render(<NotRead at={NOW}>Not read: the guard&apos;s log could not be read.</NotRead>);
    expect(html).toContain("border-dashed");
    expect(html).toContain("Last tried 14:05.");
    const count = render(<CountStat value={undefined} label="Would have been refused" tone="deny" fill="hatched" />);
    expect(count).toContain("Not read");
    expect(count).not.toMatch(/>0</);
  });
});

describe("the charts", () => {
  it("are images with a numeric name, a table twin and a table to show", () => {
    const days = history.refusals.days ?? [];
    const html = render(<DayBars days={days} />);
    const blocked = days.reduce((sum, day) => sum + day.blocked, 0);
    const would = days.reduce((sum, day) => sum + day.wouldBlock, 0);
    expect(html).toContain(`role="img" aria-label="Last 14 days: ${blocked} refused, ${would} would have been refused"`);
    expect(html.match(/<table/g)).toHaveLength(2);
    expect(html).toContain("Show as a table");
    expect(html).toContain("Today, so far");
    expect(html).toMatch(/data-partial="" opacity="0.5"/);
  });

  it("draws a zero as an empty track with 0, never as a missing chart", () => {
    const html = render(<DayBars days={[{ date: "2026-09-28", blocked: 0, wouldBlock: 0, partial: false }, { date: "2026-09-29", blocked: 0, wouldBlock: 0, partial: true }]} />);
    expect(html).toContain('aria-label="Last 2 days: 0 refused, 0 would have been refused"');
    expect(html).toContain("<span>0</span>");
    expect(html.match(/data-bar=/g)).toHaveLength(2);
  });

  it("outlines the week still under way and says so", () => {
    const html = render(<WeekBars weeks={history.refusals.weeks} />);
    expect(html).toContain("This week so far");
    expect(html).toContain('stroke-dasharray="3 2"');
  });

  it("draws tokens from BigInts, cache reads on their own track", () => {
    const html = render(
      <TokenBars
        agent="Claude Code"
        parts={[
          { key: "input", label: "Input", value: 68_600_000n },
          { key: "output", label: "Output", value: 353_850n },
        ]}
        cacheReads={70_400_000_000n}
      />,
    );
    expect(html).toContain('aria-label="Claude Code: 68,600,000 input, 353,850 output; 70,400,000,000 re-read from cache"');
    expect(html).toContain('data-part="cache_reads"');
    expect(share(1n, 3n)).toBeCloseTo(0.3333, 3);
    expect(share(5n, 0n)).toBe(0);
  });
});

describe("the marks and pills", () => {
  it("define the hatch patterns once, hidden", () => {
    const html = render(<HatchDefs />);
    expect(html).toContain('id="iw-hatch-deny"');
    expect(html).toContain('id="iw-hatch-ink"');
    expect(html).toContain('aria-hidden="true"');
  });

  it("hide a mark from screen readers and give a pill its words", () => {
    expect(render(<OutcomeMark outcome="would_have_refused" />)).toContain('data-mark-fill="hatched"');
    const pill = render(<StatusPill state="monitor" words="Monitor" label="Monitor: every command is checked" />);
    expect(pill).toContain('data-pill="monitor"');
    expect(pill).toContain('<span class="sr-only">Monitor: every command is checked</span>');
    expect(render(<StatusPill state="checking" words="Checking" />)).toContain('data-pill="unknown"');
    expect(render(<ModePill mode="monitor" />)).toContain("Decided in monitor");
    expect(render(<ModePill mode="enforce" />)).toContain("Decided in enforce");
  });
});

describe("the rows", () => {
  const item = page.items[0];

  it("draw a decision as a link, its whole command in the title, a plain cd muted and kept", () => {
    const decision: Decision = { ...item, command: "cd /Users/me/my-app && rm -rf node_modules/.cache", project: "my-app" };
    const html = render(<DecisionRow decision={decision} href={`?view=activity&decision=${encodeURIComponent(item.id)}`} />);
    expect(html).toContain(`href="?view=activity&amp;decision=${encodeURIComponent(item.id).replace(/&/g, "&amp;")}"`);
    expect(html).toContain('title="cd /Users/me/my-app &amp;&amp; rm -rf node_modules/.cache"');
    expect(html).toContain('<span data-muted="true" class="text-(--iw-ink-3)">cd /Users/me/my-app &amp;&amp; </span>');
    expect(html).toContain("line-clamp-2");
    expect(html).toContain('in <span class="font-mono">my-app</span>');
  });

  it("draw a reason with the outcome most of its decisions reached", () => {
    const reason = page.reasons.find((entry) => entry.key === "rule:download_and_execute")!;
    const html = render(<ReasonRow reason={reason} href="?view=activity&amp;reason=x" />);
    expect(html).toContain("Would have been refused");
    expect(html).toContain(reason.short);
  });

  it("draw a session with its span in the reader's clock and its outcomes", () => {
    const sessions = readSessionsPage(sessionsFixture);
    const html = render(<SessionRow session={sessions.items[0]} href="?view=activity&amp;session=x" />);
    // It ran across four days: each end says its day.
    expect(html).toContain("25 Sept, 22:26 to 29 Sept, 14:03");
    expect(html).toContain("67 decisions, 16 flagged");
    const sameDay = { ...sessions.items[0], firstAt: "2026-09-29T16:12:00Z", lastAt: "2026-09-29T17:14:00Z" };
    expect(render(<SessionRow session={sameDay} href="?view=activity&amp;session=x" />)).toContain("16:12 to 17:14");
  });

  it("list connected agents first, then those found here, then how many more", () => {
    const html = render(<AgentStrip agents={facts.agents} unnamed={facts.unnamed} max={2} />);
    expect(html.indexOf("Claude Code")).toBeLessThan(html.indexOf("Codex"));
    expect(html).toContain("+2 more on Agents");
  });

  it("say whether an agent was seen working, dashed when it was not or cannot be told", () => {
    const gemini = facts.agents.find((agent) => agent.id === "gemini")!;
    expect(render(<SeenCell agent={gemini} unnamed={{}} />)).toContain("Nothing screened yet");
    expect(render(<SeenCell agent={gemini} unnamed={{ mcp: "2026-09-29T14:00:00Z" }} />)).toContain("Not reported");
    expect(render(<SeenCell agent={{ ...gemini, mcp: { stdio: 0, wrapped: 0, remote: 1 } }} unnamed={{}} />)).toContain("No MCP server to screen");
    expect(render(<SeenCell agent={facts.agents.find((agent) => agent.id === "cursor")!} unnamed={{}} />)).toContain("Screened");
  });
});
