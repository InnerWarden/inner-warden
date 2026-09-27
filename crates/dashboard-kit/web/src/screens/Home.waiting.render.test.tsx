import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Overview } from "../api";
import { caseQueueUrl } from "../App";
import { OverviewScreen, WaitingLine, waitingAcrossLanes, waitingCount, waitingLine, type QueueOpenOptions } from "./Home";
import { readCaseViewState } from "../components/CaseFilters";
import { laneParameter, type LaneCard } from "../lanes";
import hostWaitingOverview from "../../tests/fixtures/enterprise/overview-host-waiting.json";
import serverLanesOverview from "../../tests/fixtures/enterprise/overview-lanes.json";

/**
 * "Waiting on you" read 1 on the Overview's banner, 2 on the agent's card,
 * 145 on Cases and 257 on the list the card opened. The paid host now owns
 * one definition and one count, the list its Cases filter status=waiting
 * shows, and the Overview reads that count, names the part of it that is
 * today's, and opens exactly that list.
 */

const noop = () => undefined;
const withAddresses = { ...serverLanesOverview, host_attention: hostWaitingOverview.host_attention } as unknown as Overview;

function render(overview: Overview): string {
  return renderToStaticMarkup(
    <OverviewScreen overview={overview} edition="enterprise" onOpenActivity={noop} onOpenCase={noop} onOpenQueue={noop} onOpenLane={noop} />,
  );
}

type Element = { type: unknown; props: Record<string, unknown> };
function buttons(node: unknown, found: Element[] = []): Element[] {
  if (Array.isArray(node)) {
    for (const child of node) buttons(child, found);
    return found;
  }
  if (typeof node !== "object" || node === null || !("props" in node)) return found;
  const element = node as Element;
  if (typeof element.type === "function") return buttons((element.type as (props: Record<string, unknown>) => unknown)(element.props), found);
  if (element.type === "button") found.push(element);
  buttons(element.props.children, found);
  return found;
}

describe("the server's one waiting count", () => {
  it("is read when it is a whole count over a span this bundle knows", () => {
    expect(waitingCount({ count: 145, window: "all", today: 1 })).toEqual({ count: 145, window: "all", today: 1 });
    expect(waitingCount({ count: 0, window: "7d" })).toEqual({ count: 0, window: "7d" });
  });

  it("is read as not sent when its count or span cannot be trusted", () => {
    for (const bad of [undefined, null, [], { count: -1, window: "all" }, { count: 1.5, window: "all" }, { count: "3", window: "all" }, { count: 3, window: "fortnight" }, { count: 3 }]) {
      expect(waitingCount(bad), JSON.stringify(bad)).toBeUndefined();
    }
  });

  it("drops a today that is not a whole count no larger than the total, and keeps the total", () => {
    expect(waitingCount({ count: 3, window: "all", today: 4 })).toEqual({ count: 3, window: "all" });
    expect(waitingCount({ count: 3, window: "all", today: -1 })).toEqual({ count: 3, window: "all" });
  });
});

describe("the waiting line", () => {
  /**
   * FAILS ON REVERT: print today's part as if it were the whole ("1 needs
   * you") and the 144 older cases vanish from the Overview again.
   */
  it("gives the whole count, and names the part that is today's", () => {
    expect(waitingLine({ count: 145, window: "all", today: 1 })).toEqual({
      tone: "waiting",
      title: "145 cases are waiting on you",
      span: "Counted over all time.",
      body: "1 arrived today; 144 more are from earlier days.",
      through: { label: "See the 145 waiting cases", window: "all" },
    });
    expect(waitingLine({ count: 3, window: "all", today: 3 }).body).toBe("All of them arrived today.");
    expect(waitingLine({ count: 3, window: "all", today: 0 }).body).toBe("None of them arrived today; they are from earlier days.");
    expect(waitingLine({ count: 3, window: "all", today: 2 }).body).toBe("2 arrived today; 1 more is from earlier days.");
    expect(waitingLine({ count: 3, window: "all" }).body).toBeUndefined();
  });

  it("says one case in the singular", () => {
    expect(waitingLine({ count: 1, window: "7d", today: 0 })).toEqual({
      tone: "waiting",
      title: "1 case is waiting on you",
      span: "Counted over the last 7 days.",
      body: "It is from an earlier day.",
      through: { label: "See the waiting case", window: "7d" },
    });
    expect(waitingLine({ count: 1_298, window: "24h" }).title).toBe("1,298 cases are waiting on you");
  });

  /**
   * A count over all time read "145 cases are waiting on you" with no span,
   * under cards that each say "in the last 7 days", so the page showed two
   * counts that seemed to disagree and did not say why. Every span is named,
   * all time included, in the one set of words every window control uses.
   *
   * FAILS ON REVERT: name no span for all time and the line reads as a count
   * of the cards' week.
   */
  it("names the span it was counted over, every span, all time included", () => {
    expect(waitingLine({ count: 145, window: "all" }).span).toBe("Counted over all time.");
    expect(waitingLine({ count: 3, window: "1h" }).span).toBe("Counted over the last hour.");
    expect(waitingLine({ count: 3, window: "30d" }).span).toBe("Counted over the last 30 days.");
    const html = renderToStaticMarkup(<WaitingLine overview={{ ...withAddresses, waiting: { count: 145, window: "all", today: 1 } }} />);
    expect(html).toContain("Counted over all time.");
  });

  it("is calm and offers no empty list when nothing waits", () => {
    expect(waitingLine({ count: 0, window: "all" })).toEqual({ tone: "quiet", title: "Nothing is waiting on you", span: "Counted over all time.", body: "No case on this host needs a person." });
    expect(waitingLine({ count: 0, window: "7d" }).span).toBe("Counted over the last 7 days.");
  });
});

describe("on the Overview", () => {
  it("replaces the address line and its definitions when the server sends the count", () => {
    const html = render({ ...withAddresses, waiting: { count: 145, window: "all", today: 1 } });
    expect(html).toContain("145 cases are waiting on you");
    expect(html).toContain("1 arrived today; 144 more are from earlier days.");
    expect(html).toContain('data-waiting-count="145"');
    expect(html).not.toContain("What this number counts");
    expect(html).not.toContain("addresses are waiting on you");
  });

  it("reads the address line exactly as before on a host that sends no count", () => {
    const html = render(withAddresses);
    expect(html).not.toContain("data-waiting-count");
    expect(html).toContain("waiting on you");
    expect(render({ ...withAddresses, waiting: { count: "lots", window: "all" } } as unknown as Overview)).toBe(html);
  });

  /**
   * The link opens exactly the list the number counted: the waiting filter,
   * in the server's span.
   *
   * FAILS ON REVERT: open the queue without the span and a 7-day count opens
   * every day's list.
   */
  /**
   * The count is every lane's, so the list it opens is every lane's:
   * `lane=everything`. With no lane in the address the Cases screen opens
   * ONE lane (the one last used, or the agent's or the server's), and "See
   * the 145 waiting cases" listed one lane's waiting cases under a count of
   * all of them.
   *
   * FAILS ON REVERT: leave the lane out and the Cases screen picks one.
   */
  it("opens exactly the list it counted: the waiting filter, every lane, the server's span", () => {
    const opened: (QueueOpenOptions | undefined)[] = [];
    const tree = WaitingLine({ overview: { ...withAddresses, waiting: { count: 4, window: "7d" } }, onOpenQueue: (options) => void opened.push(options) });
    const [link] = buttons(tree);
    (link.props.onClick as () => void)();
    expect(opened).toEqual([{ window: "7d" }]);
    const url = caseQueueUrl("https://dashboard.test/?view=overview", "7d");
    expect(url.searchParams.get("status")).toBe("waiting");
    expect(url.searchParams.get("window")).toBe("7d");
    expect(url.searchParams.get("lane")).toBe("everything");
    // What the Cases screen reads back from that address: every case.
    const view = readCaseViewState(url.search);
    expect(view.lane).toBe("everything");
    expect(laneParameter(view.lane as "everything")).toBe("");
    expect(caseQueueUrl("https://dashboard.test/?view=overview").searchParams.get("window")).toBe("all");
    expect(caseQueueUrl("https://dashboard.test/?view=cases&lane=server_attacks").searchParams.get("lane")).toBe("everything");
  });

  it("offers no link without a Cases screen", () => {
    const html = renderToStaticMarkup(<WaitingLine overview={{ ...withAddresses, waiting: { count: 4, window: "7d" } }} />);
    expect(html).toContain("4 cases are waiting on you");
    expect(html).toContain("Counted over the last 7 days.");
    expect(html).not.toContain("<button");
  });
});

/**
 * The line counts every lane; each card's chip counts its own lane in its
 * card's span. A new server read "3 cases ... are waiting on you" over one
 * "2 waiting on you" chip, and nothing said where the third one was.
 */
describe("the waiting count beside the lane cards", () => {
  const card = (lane: "agent_messages" | "agent_actions" | "server_attacks", waiting: number | undefined, window: "7d" | "all" = "7d"): LaneCard => ({
    lane, state: "available", count: 10, window, sentence: "x", ...(waiting === undefined ? {} : { waiting }),
  });

  /**
   * FAILS ON REVERT: compare nothing and the third case is unaccounted for.
   */
  it("says how many are outside the lanes when the chips add up to less", () => {
    const cards = [card("agent_messages", 0), card("agent_actions", 2), card("server_attacks", 0)];
    expect(waitingAcrossLanes({ count: 3, window: "7d" }, cards)).toBe("1 more is outside the lanes above.");
    expect(waitingAcrossLanes({ count: 5, window: "7d" }, cards)).toBe("3 more are outside the lanes above.");
    const html = renderToStaticMarkup(<WaitingLine overview={{ ...withAddresses, waiting: { count: 3, window: "7d" } }} cards={cards} />);
    expect(html).toContain("1 more is outside the lanes above.");
  });

  it("says which span the cards count when it is not the count's", () => {
    const cards = [card("agent_messages", 0), card("agent_actions", 2), card("server_attacks", 1)];
    expect(waitingAcrossLanes({ count: 145, window: "all" }, cards)).toBe("The cards above count the last 7 days.");
  });

  it("says nothing it cannot back", () => {
    const even = [card("agent_messages", 1), card("agent_actions", 2), card("server_attacks", 0)];
    expect(waitingAcrossLanes({ count: 3, window: "7d" }, even)).toBeUndefined();
    // The server's lane sent no waiting count: nothing to add up.
    expect(waitingAcrossLanes({ count: 3, window: "7d" }, [card("agent_actions", 2), card("server_attacks", undefined)])).toBeUndefined();
    // Chips beyond the total: this page cannot say why.
    expect(waitingAcrossLanes({ count: 1, window: "7d" }, even)).toBeUndefined();
    // Cards over mixed spans: the intro already says so.
    expect(waitingAcrossLanes({ count: 3, window: "7d" }, [card("agent_actions", 2), card("server_attacks", 0, "all")])).toBeUndefined();
    expect(waitingAcrossLanes({ count: 0, window: "7d" }, [card("agent_actions", 0)])).toBeUndefined();
    expect(waitingAcrossLanes({ count: 3, window: "7d" }, undefined)).toBeUndefined();
  });

  it("is drawn on the lanes Overview from the cards above it", () => {
    // The fixture's cards count different spans, which the intro says; here
    // every card counts the last 7 days.
    const lanes = structuredClone(serverLanesOverview.lanes) as Record<string, Record<string, unknown>>;
    for (const lane of Object.values(lanes)) lane.window = "7d";
    const html = render({ ...withAddresses, lanes, waiting: { count: 145, window: "all", today: 1 } } as unknown as Overview);
    expect(html).toContain("The cards above count the last 7 days.");
    expect(render({ ...withAddresses, waiting: { count: 145, window: "all", today: 1 } })).not.toContain("The cards above count");
  });
});
