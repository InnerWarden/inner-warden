import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { DecisionProvenance, PROVENANCE_DECIDABLE_NOTE } from "./DecisionProvenance";

/**
 * THE DEFECT THIS PINS: the note read "use the decision below" after the
 * decision moved to the top of the case, sending the reader down the page
 * for a control above them. It names the control, not a place.
 *
 * FAILS ON REVERT: put "below" back and this sees it.
 */
describe("the decision record's note", () => {
  it("names the case's decision buttons without saying where they are", () => {
    const html = renderToStaticMarkup(<DecisionProvenance events={[]} feedback={[]} decidable />);
    expect(html).toContain(PROVENANCE_DECIDABLE_NOTE);
    for (const place of ["below", "above", "beneath", "under"]) expect(PROVENANCE_DECIDABLE_NOTE).not.toContain(place);
  });

  it("keeps the read-only sentence where the screen offers no decision", () => {
    const html = renderToStaticMarkup(<DecisionProvenance events={[]} feedback={[]} />);
    expect(html).toContain("Nothing on this screen changes a rule, an allowlist or a policy.");
  });
});
