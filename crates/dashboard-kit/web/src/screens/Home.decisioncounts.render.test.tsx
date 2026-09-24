import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { DecisionCounts } from "./Home";

/**
 * THE DEFECT THIS PINS
 *
 * The tile read "Needs review" / "Requires human judgement" and counted the
 * agent guardrail's `review` verdicts. A paid host's Cases screen offers a
 * "Needs review" status too, and that is a case status, not a guardrail
 * verdict. One paid Overview read 0 here while Cases listed hundreds of rows
 * under the same two words, and a reader had no way to tell they were
 * different things.
 *
 * These RENDER the tiles and read the words the screen prints. Putting the old
 * label back on the tile makes the first test fail.
 */

function render(reviewVerdicts: number): string {
  return renderToStaticMarkup(
    <DecisionCounts
      commands={40}
      sessions={2}
      denyVerdicts={0}
      reviewVerdicts={reviewVerdicts}
      allowVerdicts={40 - reviewVerdicts}
    />,
  );
}

/** The one tile whose label is `label`, as rendered. */
function tile(html: string, label: string): string {
  const found = html.split("<article").find((part) => part.includes(`>${label}</div>`));
  if (found === undefined) throw new Error(`no tile labelled ${label} in ${html}`);
  return found;
}

describe("the review tile says whose verdict it counts", () => {
  it("names the agent guardrail, not a bare Needs review", () => {
    const html = render(3);
    const review = tile(html, "Agent actions flagged for review");
    expect(review).toContain(">3</div>");
    expect(review).toContain("The agent guardrail asked for a person&#x27;s judgement");
    // The two words a paid Cases screen uses for a case status must not label
    // this count, or the page contradicts itself again.
    expect(html).not.toContain(">Needs review</div>");
    expect(html).not.toContain("Requires human judgement");
  });

  it("keeps the attention tone for a non-zero count, and drops it at zero", () => {
    expect(tile(render(3), "Agent actions flagged for review")).toContain("text-amber-700");
    const quiet = tile(render(0), "Agent actions flagged for review");
    expect(quiet).toContain(">0</div>");
    expect(quiet).not.toContain("text-amber-700");
  });
});
