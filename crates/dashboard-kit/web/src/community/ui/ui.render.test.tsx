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
import { AgentRow, AgentStrip, DecisionRow, ReasonRow, SeenCell, SessionRow } from "./rows";
import { CopyCommand } from "../parts";

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

  /** Restarts with no command before them are the step itself: "now". FAILS ON REVERT of `when="now"` in the band. */
  it("asks for a restart now where the band has no command, never after a step that is not there", () => {
    const changed = facts.agents
      .filter((agent) => agent.id === "claude-code")
      .map((agent) => ({ ...agent, lastObservedAt: "2026-09-27T13:00:00Z", configChangedAt: "2026-09-27T14:05:00Z" }));
    const verdict = overviewVerdict({ metaStatus: "ready", meta: {}, health: { recording: true }, agents: changed, agentsFailed: false, unnamed: {}, now: NOW });
    expect(verdict.row).toBe(6);
    const html = render(<VerdictBand verdict={verdict} />);
    expect(html).toContain("If Claude Code is running, restart it now.");
    expect(html).not.toContain("after this step");
    expect(html).not.toContain("data-command");
  });

  /** Some agents refuse a deny and others do not: the half shield, as in the header, never the monitor eye. */
  it("draws the mixed band with the half shield", () => {
    const enforce = facts.agents.filter((agent) => agent.id === "cursor");
    const monitor = facts.agents.filter((agent) => agent.id === "claude-code");
    const verdict = overviewVerdict({ metaStatus: "ready", meta: {}, health: { recording: true }, agents: [...monitor, ...enforce], agentsFailed: false, unnamed: {}, now: NOW });
    expect(verdict.row).toBe(7);
    const html = render(<VerdictBand verdict={verdict} />);
    expect(html).toContain('data-icon="half-shield"');
    expect(html).not.toContain('data-icon="eye"');
    const monitorOnly = overviewVerdict({ metaStatus: "ready", meta: {}, health: { recording: true }, agents: monitor, agentsFailed: false, unnamed: {}, now: NOW });
    expect(render(<VerdictBand verdict={monitorOnly} />)).toContain('data-icon="eye"');
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

  /** Dashed means not read on these pages: the week under way is known, so it is drawn at half strength, never dashed. */
  it("draws the week still under way at half strength, says so, and never dashes it", () => {
    const html = render(<WeekBars weeks={history.refusals.weeks} />);
    expect(html).toContain("This week so far");
    expect(html).toMatch(/data-partial="" opacity="0.5"/);
    expect(html).not.toContain("stroke-dasharray");
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
    // A key on screen says what each shade is: the shades are never the only signal.
    const key = html.slice(html.indexOf("data-token-key"), html.indexOf("</figcaption>"));
    expect(key.replace(/<[^>]+>/g, "|")).toMatch(/\|Input\|.*\|Output\|.*\|Re-read from cache\|/);
    expect(key.match(/aria-hidden="true"/g)).toHaveLength(3);
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
    expect(html).toContain("line-clamp-2 lg:line-clamp-3");
    expect(html).toContain('in <span class="font-mono">my-app</span>');
  });

  it("draw a reason with the outcome its decisions reached", () => {
    const reason = page.reasons.find((entry) => entry.key === "rule:download_and_execute")!;
    const html = render(<ReasonRow reason={reason} href="?view=activity&amp;reason=x" />);
    expect(html).toContain("Would have been refused");
    expect(html).toContain(reason.short);
  });

  /**
   * 500 would have been refused and 3 refused before they ran: the row says
   * both, each with its count, and its mark is the more severe one. FAILS ON
   * REVERT to the dominant outcome alone ("503, Would have been refused").
   */
  it("draw every outcome a reason reached, the most severe never hidden behind the most frequent", () => {
    const reason = { key: "rule:x", words: "x", short: "Downloads and runs a script", count: 503, byOutcome: { would_have_refused: 500, refused_before_run: 3 } };
    const html = render(<ReasonRow reason={reason} href="?view=activity&amp;reason=x" />);
    const outcomes = [...html.matchAll(/data-reason-outcome="([a-z_]+)"/g)].map((match) => match[1]);
    expect(outcomes).toEqual(["refused_before_run", "would_have_refused"]);
    const text = html.replace(/<[^>]+>/g, "");
    expect(text).toContain("3Refused before it ran");
    expect(text).toContain("500Would have been refused");
    // The row's own mark is the most severe outcome's.
    expect(html.indexOf('data-mark-tone="stopped"')).toBeLessThan(html.indexOf("Downloads and runs a script"));
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
    expect(render(<SeenCell agent={gemini} unnamed={{}} now={NOW} />)).toContain("Nothing since its settings changed on 27 Sept at 14:05");
    expect(render(<SeenCell agent={{ ...gemini, configChangedAt: undefined }} unnamed={{}} />)).toContain("Nothing screened yet");
    expect(render(<SeenCell agent={gemini} unnamed={{ mcp: "2026-09-29T14:00:00Z" }} />)).toContain("Not reported");
    expect(render(<SeenCell agent={facts.agents.find((agent) => agent.id === "cursor")!} unnamed={{}} />)).toContain("Screened");
  });

  /**
   * A screening older than the settings change is not the guard seen
   * working: the band and the summary count it as not seen, and so does the
   * cell. FAILS ON REVERT of the `seen` branch ("Screened 2 minutes ago").
   */
  it("never draw a screening from before the settings changed as Screened", () => {
    const gemini = facts.agents.find((agent) => agent.id === "gemini")!;
    const before = { ...gemini, lastObservedAt: "2026-09-27T13:00:00Z", configChangedAt: "2026-09-27T14:05:00Z" };
    const html = render(<SeenCell agent={before} unnamed={{}} now={NOW} />);
    expect(html).toContain('data-seen="not_seen"');
    expect(html).not.toContain('data-seen="screened"');
    expect(html).toContain("Nothing since its settings changed on 27 Sept at 14:05");
    expect(html).toContain('title="Last screened');
    const after = render(<SeenCell agent={{ ...before, lastObservedAt: "2026-09-27T15:00:00Z" }} unnamed={{}} now={NOW} />);
    expect(after).toContain('data-seen="screened"');
  });

  /** A proxy with no local server and a remote one: the remote one is said as not screened. */
  it("say a remote server is not screened where there is no local one to screen", () => {
    const gemini = facts.agents.find((agent) => agent.id === "gemini")!;
    expect(render(<SeenCell agent={{ ...gemini, mcp: { stdio: 0, wrapped: 0, remote: 1 } }} unnamed={{}} />)).toContain(
      "No local MCP server to screen. 1 remote not screened.",
    );
    const none = render(<SeenCell agent={{ ...gemini, mcp: { stdio: 0, wrapped: 0, remote: 0 } }} unnamed={{}} />);
    expect(none).toContain("No MCP server to screen");
    expect(none).not.toContain("remote");
  });

  /** A mode that could not be read is the Unknown pill, never "Not connected". */
  it("draw an agent whose mode could not be read as unknown, never as not connected", () => {
    const codex = facts.agents.find((agent) => agent.id === "codex")!;
    const html = render(<AgentRow agent={{ ...codex, mode: "unknown" }} unnamed={{}} />);
    expect(html).toContain('data-pill="unknown"');
    expect(html).toContain("Its mode could not be read.");
    expect(html).not.toContain("Not connected");
    const strip = render(<AgentStrip agents={[{ ...codex, mode: "unknown", present: false }]} unnamed={{}} />);
    expect(strip).toContain('data-agent-row="codex"');
    expect(strip).not.toContain("Not connected");
  });

  /** "Copied" is said to a screen reader in a polite live region; the button's name stays the command. */
  it("give Copy a polite live region, empty until a copy worked", () => {
    const html = render(<CopyCommand command="innerwarden enforce" />);
    expect(html).toContain('data-copied-status="true" class="sr-only" aria-live="polite"></span>');
    expect(html).toContain('aria-label="Copy command: innerwarden enforce"');
    expect(render(<CopyCommand command="innerwarden contain -- &lt;command&gt;" template />)).not.toContain("aria-live");
  });
});
