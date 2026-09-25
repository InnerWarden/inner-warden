import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Overview } from "../api";
import { setTechnicalDetail } from "../components/TechnicalDetail";
import { OverviewScreen } from "./Home";
import communityOverview from "../../tests/fixtures/community/overview.json";
import hostWaitingOverview from "../../tests/fixtures/enterprise/overview-host-waiting.json";
// Both written by the paid server's own tests, not by hand. The server's
// test builds the lanes without the host's waiting line, so the page below
// adds the one an older paid host sent, to show both on one screen.
import serverLanesOverview from "../../tests/fixtures/enterprise/overview-lanes.json";
import noSourceOverview from "../../tests/fixtures/enterprise/overview-lanes-no-source.json";

const lanesOverview = { ...serverLanesOverview, host_attention: hostWaitingOverview.host_attention };

/**
 * The Overview, RENDERED from a payload handed in, in both layouts.
 *
 * Without `lanes` the page must be the page it always was: an older server,
 * paid or free, sends none of the new fields, and nothing about it may move.
 * The markup is pinned in files written from the layout before lanes existed
 * (checked element for element against the previous build in a browser), so
 * any change to that layout is a failing diff here, not a surprise on a host.
 *
 * With `lanes` the three cards lead, and the numbers the page used to lead
 * with are behind the technical switch, whole.
 */

const noop = () => undefined;
// A richer meta for the pinned pages, so the hero's mode badge and the
// configured-agents line are in the markup too.
const monitorMeta = (edition: "community" | "enterprise") => ({ meta: { edition, guardrail: { mode: "monitor", guarded_agents: 1 } } });

function render(overview: unknown, edition: "community" | "enterprise", extra: Partial<Parameters<typeof OverviewScreen>[0]> = {}): string {
  return renderToStaticMarkup(
    <OverviewScreen
      overview={overview as Overview}
      meta={{ edition }}
      edition={edition}
      onOpenActivity={noop}
      onOpenCase={edition === "enterprise" ? noop : undefined}
      onOpenQueue={edition === "enterprise" ? noop : undefined}
      onOpenLane={edition === "enterprise" ? noop : undefined}
      {...extra}
    />,
  );
}

beforeEach(() => {
  // Recent activity prints relative times; the pinned markup needs one clock.
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-09-25T12:00:00Z"));
  setTechnicalDetail(false);
});

afterEach(() => {
  setTechnicalDetail(false);
  vi.useRealTimers();
});

describe("an Overview whose host sends no lanes", () => {
  /**
   * THE RULE THIS PINS: an older server renders exactly as today.
   *
   * FAILS ON REVERT: take the lanes layout for a payload without `lanes`
   * (or change anything in the layout without them) and these diffs fail.
   */
  it("renders the Community page exactly as it was", async () => {
    await expect(render(communityOverview, "community", monitorMeta("community"))).toMatchFileSnapshot("./__snapshots__/overview-community-no-lanes.html");
  });

  it("renders the paid page exactly as it was, in both views", async () => {
    await expect(render(hostWaitingOverview, "enterprise", monitorMeta("enterprise"))).toMatchFileSnapshot("./__snapshots__/overview-enterprise-no-lanes.html");
    setTechnicalDetail(true);
    await expect(render(hostWaitingOverview, "enterprise", monitorMeta("enterprise"))).toMatchFileSnapshot("./__snapshots__/overview-enterprise-no-lanes-technical.html");
  });

  it("has no lane card and keeps the posture hero as the page heading", () => {
    const html = render(hostWaitingOverview, "enterprise");
    expect(html).not.toContain("data-lane=");
    expect(html).toContain('<h1 id="posture-title"');
  });
});

describe("an Overview whose host answers the three questions", () => {
  it("leads with one card per lane under one page heading", () => {
    const html = render(lanesOverview, "enterprise");
    expect(html.match(/data-lane="/g)).toHaveLength(3);
    expect(html.match(/<h1/g)).toHaveLength(1);
    expect(html).toContain('<h1 id="lanes-title"');
    expect(html.indexOf('data-lane="agent_messages"')).toBeLessThan(html.indexOf("host-attention-title"));
  });

  /**
   * THE RULE THIS PINS: the plain view is the three answers. The numbers the
   * page used to lead with are for whoever asks, behind the switch.
   *
   * FAILS ON REVERT: render the posture hero, the tiles, the operational
   * strip or the risk signals outside `TechnicalOnly` and this sees them.
   */
  it("keeps the old figures behind the technical switch", () => {
    const html = render(lanesOverview, "enterprise");
    expect(html).not.toContain("posture-title");
    expect(html).not.toContain("Recorded decisions");
    expect(html).not.toContain("What the guardrail actually did");
    expect(html).not.toContain("Risk signals");
    expect(html).not.toContain("local-agents-title");
    expect(html).not.toContain("The records behind these cards");
  });

  it("shows every one of them, whole, in the technical view", () => {
    setTechnicalDetail(true);
    const html = render(lanesOverview, "enterprise");
    expect(html).toContain("The records behind these cards");
    expect(html).toContain('<h2 id="posture-title"');
    expect(html.match(/<h1/g)).toHaveLength(1);
    expect(html).toContain("Recorded decisions");
    expect(html).toContain("What the guardrail actually did");
    expect(html).toContain("Risk signals");
    expect(html).toContain("local-agents-title");
    // The cards stay on top in both views.
    expect(html.indexOf('data-lane="agent_messages"')).toBeLessThan(html.indexOf("posture-title"));
  });

  /**
   * Never hide the existence of something waiting: the host's waiting line
   * and the recent decisions stay in the plain view.
   */
  it("keeps what is waiting and what just happened in the plain view", () => {
    const html = render(lanesOverview, "enterprise");
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).toContain("Recent activity");
    expect(html).toContain("The kernel stopped sudo");
  });

  /**
   * A decision record that is flagging something is a thing to do, so it
   * stays visible without its tiles. A calm one is the agent card's evidence
   * and moves behind the switch with them.
   *
   * FAILS ON REVERT: gate the record on the switch alone and the flagged
   * actions vanish from the plain view.
   */
  it("keeps a decision record that flags something, without its tiles", () => {
    const flagged = { ...lanesOverview, review: 2, review_verdicts: 2 };
    const html = render(flagged, "enterprise");
    expect(html).toContain("2 agent actions were flagged for review");
    expect(html).not.toContain("Recorded decisions");
    const calm = render(lanesOverview, "enterprise");
    expect(calm).not.toContain("decision-summary-title");
  });

  /**
   * "View all in Cases" beside the record opens the agent's lane on a host
   * that files cases into lanes, and the sentence says so instead of asking
   * the reader to set a filter by hand.
   */
  it("sends the record's reader to the agent's lane and says so", () => {
    const flagged = { ...lanesOverview, review: 2, review_verdicts: 2 };
    const html = render(flagged, "enterprise");
    expect(html).toContain("View all in Cases opens them under What your AI agent did.");
    expect(html).not.toContain("set Capability");
  });

  it("draws a lane with no source without a number, beside the lanes that have one", () => {
    const html = render(noSourceOverview, "enterprise");
    expect(html.match(/data-lane="/g)).toHaveLength(3);
    expect(html.match(/data-lane-state="no_source"/g)).toHaveLength(1);
    expect(html.match(/data-lane-count/g)).toHaveLength(2);
  });

  it("draws only the lanes it can read", () => {
    const { server_attacks: _dropped, ...twoLanes } = serverLanesOverview.lanes;
    const html = render({ ...lanesOverview, lanes: twoLanes }, "enterprise");
    expect(html.match(/data-lane="/g)).toHaveLength(2);
    expect(html).not.toContain('data-lane="server_attacks"');
  });

  /**
   * THE DEFECT THIS PINS: the kit read lanes named `prompt`, `agent` and
   * `host`, and the server sends `agent_messages`, `agent_actions` and
   * `server_attacks`, so on a real host the Overview never took the lanes
   * layout at all. This renders the server's own payload.
   *
   * FAILS ON REVERT: read the old names and this page has no lane card.
   */
  it("takes the lanes layout from the payload the server sends", () => {
    const html = render(serverLanesOverview, "enterprise");
    expect(html).toContain('<h1 id="lanes-title"');
    expect(html.match(/data-lane="/g)).toHaveLength(3);
  });

  /**
   * On this layout the agent and token panels follow the shell: a source the
   * host reports as not configured has no tab and no panel.
   */
  it("leaves out an agent or token panel the shell says is not configured", () => {
    setTechnicalDetail(true);
    const neither = render(lanesOverview, "enterprise", { machinePanels: { agents: false, tokens: false } });
    expect(neither).not.toContain("local-agents-title");
    expect(neither).not.toContain("token-intelligence-title");
    const agentsOnly = render(lanesOverview, "enterprise", { machinePanels: { agents: true, tokens: false } });
    expect(agentsOnly).toContain("local-agents-title");
  });

  it("keeps Community's own panels when a free host answers the lanes", () => {
    const html = render(lanesOverview, "community");
    expect(html).toContain("What Community includes");
    expect(html).toContain('data-ad-state="offer"');
  });
});
