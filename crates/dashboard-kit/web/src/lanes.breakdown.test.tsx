import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { LaneCards } from "./components/LaneCards";
import { laneBreakdown, overviewLaneCards, parseLaneCard, type LaneCard } from "./lanes";
import lanesOverview from "../tests/fixtures/enterprise/overview-lanes.json";

/**
 * The agent's card read "8 in the last 7 days" over "tried 7 commands" and a
 * split of 2 refused, 4 stopped by the kernel and 3 that may have run, which
 * is 9. Three numbers, three answers. The host may now send the split
 * itself, and the card shows it only when it adds up to the headline.
 */

const agent = lanesOverview.lanes.agent_actions;
const split = [
  { key: "refused_before_run", count: 1, label: "refused before they ran" },
  { key: "kernel_stopped", count: 1, label: "stopped by the kernel" },
  { key: "may_have_run", count: 0, label: "judged unsafe and may have run" },
];

describe("the split of a card's number", () => {
  it("is read when its parts add up to the headline", () => {
    const card = parseLaneCard("agent_actions", { ...agent, breakdown: split }) as Extract<LaneCard, { state: "available" }>;
    expect(card.count).toBe(2);
    expect(card.breakdown).toEqual(split);
  });

  /**
   * FAILS ON REVERT: take the parts without checking their sum and the card
   * prints 2 + 4 + 3 under an 8 again.
   */
  it("is dropped whole when the parts do not add up to the headline", () => {
    expect(laneBreakdown([{ key: "a", count: 2, label: "x" }, { key: "b", count: 4, label: "y" }, { key: "c", count: 3, label: "z" }], 8)).toBeUndefined();
    expect(laneBreakdown([{ key: "a", count: 2, label: "x" }], 8)).toBeUndefined();
    const card = parseLaneCard("agent_actions", { ...agent, breakdown: [...split, { key: "extra", count: 1, label: "more" }] });
    expect(card).toBeDefined();
    expect(card && "breakdown" in card).toBe(false);
  });

  it("is dropped whole over one malformed part, and never costs the card", () => {
    for (const bad of [
      [{ key: "Refused", count: 2, label: "x" }],
      [{ key: "a", count: -1, label: "x" }, { key: "b", count: 3, label: "y" }],
      [{ key: "a", count: 1.5, label: "x" }, { key: "b", count: 0.5, label: "y" }],
      [{ key: "a", count: 2, label: "" }],
      [{ key: "a", count: 2, label: "bad\u0007label" }],
      // A C1 control, and a right to left override that would reorder the
      // words printed after it.
      [{ key: "a", count: 2, label: "bad\u0085label" }],
      [{ key: "a", count: 2, label: "refused \u202Enur ot\u202C" }],
      [{ key: "a", count: 2, label: "isolated \u2067x\u2069" }],
      [{ key: "a", count: 1, label: "x" }, { key: "a", count: 1, label: "y" }],
      ["a", "b"],
      [],
      "2 refused",
    ]) {
      expect(laneBreakdown(bad, 2), JSON.stringify(bad)).toBeUndefined();
      const card = parseLaneCard("agent_actions", { ...agent, breakdown: bad });
      expect(card?.state).toBe("available");
    }
  });

  it("is absent on a host that sends none, and the card is as it was", () => {
    const cards = overviewLaneCards(lanesOverview.lanes) as LaneCard[];
    expect(cards.some((card) => card.state === "available" && card.breakdown !== undefined)).toBe(false);
    expect(renderToStaticMarkup(<LaneCards cards={cards} edition="enterprise" />)).not.toContain("data-lane-breakdown");
  });

  it("is drawn under the number, one line per part with something in it, in the host's words", () => {
    const card = parseLaneCard("agent_actions", { ...agent, breakdown: split }) as LaneCard;
    const html = renderToStaticMarkup(<LaneCards cards={[card]} edition="enterprise" />);
    expect(html).toContain("data-lane-breakdown");
    expect(html.match(/data-part="/g)).toHaveLength(2);
    expect(html).toContain(">refused before they ran<");
    expect(html).toContain(">stopped by the kernel<");
    expect(html).not.toContain("may have run<");
    expect(html.indexOf("data-lane-count")).toBeLessThan(html.indexOf("data-lane-breakdown"));
  });

  /**
   * A split that adds up because every part is zero, under a card of zero,
   * is a valid answer with nothing to draw.
   *
   * FAILS ON REVERT: draw the list around the filter and an empty list with
   * its margin is announced as a list of no items.
   */
  it("draws no list at all when no part has anything in it", () => {
    const empty = [{ key: "refused_before_run", count: 0, label: "refused before they ran" }];
    expect(laneBreakdown(empty, 0)).toEqual(empty);
    const card = parseLaneCard("agent_actions", { ...agent, count: 0, breakdown: empty }) as LaneCard;
    const html = renderToStaticMarkup(<LaneCards cards={[card]} edition="enterprise" />);
    expect(html).not.toContain("data-lane-breakdown");
    expect(html).not.toContain("<ul");
  });
});
