import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { Overview } from "../api";
import { caseQueueUrl } from "../App";
import { OverviewScreen, WaitingLine, waitingCount, waitingLine, type QueueOpenOptions } from "./Home";
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
      body: "1 arrived today; 144 more are from earlier days.",
      through: { label: "See the 145 waiting cases", window: "all" },
    });
    expect(waitingLine({ count: 3, window: "all", today: 3 }).body).toBe("All of them arrived today.");
    expect(waitingLine({ count: 3, window: "all", today: 0 }).body).toBe("None of them arrived today; they are from earlier days.");
    expect(waitingLine({ count: 3, window: "all", today: 2 }).body).toBe("2 arrived today; 1 more is from earlier days.");
    expect(waitingLine({ count: 3, window: "all" }).body).toBeUndefined();
  });

  it("says one case in the singular, and names the span when it is not every day", () => {
    expect(waitingLine({ count: 1, window: "7d", today: 0 })).toEqual({
      tone: "waiting",
      title: "1 case from the last 7 days is waiting on you",
      body: "It is from an earlier day.",
      through: { label: "See the waiting case", window: "7d" },
    });
    expect(waitingLine({ count: 1_298, window: "24h" }).title).toBe("1,298 cases from the last 24 hours are waiting on you");
  });

  it("is calm and offers no empty list when nothing waits", () => {
    expect(waitingLine({ count: 0, window: "all" })).toEqual({ tone: "quiet", title: "Nothing is waiting on you", body: "No case on this host needs a person." });
    expect(waitingLine({ count: 0, window: "7d" }).body).toBe("No case from the last 7 days needs a person.");
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
  it("opens exactly the list it counted", () => {
    const opened: (QueueOpenOptions | undefined)[] = [];
    const tree = WaitingLine({ overview: { ...withAddresses, waiting: { count: 4, window: "7d" } }, onOpenQueue: (options) => void opened.push(options) });
    const [link] = buttons(tree);
    (link.props.onClick as () => void)();
    expect(opened).toEqual([{ window: "7d" }]);
    const url = caseQueueUrl("https://dashboard.test/?view=overview", "7d");
    expect(url.searchParams.get("status")).toBe("waiting");
    expect(url.searchParams.get("window")).toBe("7d");
    expect(caseQueueUrl("https://dashboard.test/?view=overview").searchParams.get("window")).toBe("all");
  });

  it("offers no link without a Cases screen", () => {
    const html = renderToStaticMarkup(<WaitingLine overview={{ ...withAddresses, waiting: { count: 4, window: "7d" } }} />);
    expect(html).toContain("4 cases from the last 7 days are waiting on you");
    expect(html).not.toContain("<button");
  });
});
