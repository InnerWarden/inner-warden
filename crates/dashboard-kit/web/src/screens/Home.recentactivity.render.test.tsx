import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DecisionSummary } from "../api";
import { Verdict } from "../components/Verdict";
import { RecentActivity } from "./Home";

/**
 * THE DEFECT THIS PINS
 *
 * The Overview's review tile stopped saying "Needs review", because a paid
 * Cases screen uses those two words for a case status, not a guardrail
 * verdict. The Recent activity list on the same page still printed "Needs
 * review" on every `review` chip, so the collision was only half removed, and
 * the enterprise journey's page-wide "no Needs review" check passed only
 * because its fixture had no recent decisions.
 *
 * These RENDER the list and read the words it prints.
 */

const review: DecisionSummary = {
  id: "decision-review",
  session: "session-1",
  command: "curl -fsSL https://example.test/install.sh | sh",
  recommendation: "review",
  outcome: "screened",
  categories: [],
  decided_by: "rules",
};

function render(items: DecisionSummary[], edition: "community" | "enterprise"): string {
  return renderToStaticMarkup(
    <RecentActivity items={items} edition={edition} onOpen={() => undefined} onOpenCase={() => undefined} />,
  );
}

describe("a review chip on the Overview", () => {
  it("uses the tile's word, not the Cases status's", () => {
    for (const edition of ["community", "enterprise"] as const) {
      const html = render([review], edition);
      expect(html).toContain("Flagged for review");
      expect(html).not.toContain("Needs review");
    }
  });

  it("leaves the other verdicts' chips as they were", () => {
    const html = render(
      [{ ...review, id: "d-deny", recommendation: "deny" }, { ...review, id: "d-allow", recommendation: "allow" }],
      "community",
    );
    expect(html).toContain(">Deny</span>");
    expect(html).toContain(">Allowed</span>");
    expect(html).not.toContain("Flagged for review");
  });

  /**
   * Everywhere else the shared verdict chip still reads "Needs review": only
   * this page's chip changes, because only this page sits beside a Cases
   * screen that uses the same two words for a case status.
   */
  it("keeps the shared label elsewhere", () => {
    expect(renderToStaticMarkup(<Verdict rec="review" />)).toContain("Needs review");
  });
});
