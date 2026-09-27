import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { signedInLabel } from "./App";
import { casePageCountBadge } from "./components/casePageCount";
import { Outcome, OUTCOME_CHIPS } from "./components/Outcome";
import { statusPresentation } from "./components/StatusBadge";
import { formatCount } from "./presentation";
import { agreeWithControls, dispositionReason } from "./screens/Posture";

/**
 * The wording and badge slips a first reader caught, each fixed where the
 * kit prints it.
 */

describe("one way to print a count", () => {
  /**
   * One card printed "1,298" beside "1298", and a count went through the
   * viewer's locale in one panel and a fixed one in the next.
   */
  it("groups thousands the same way for every viewer", () => {
    expect(formatCount(1298)).toBe("1,298");
    expect(formatCount(4_394_000)).toBe("4,394,000");
    expect(formatCount(-0)).toBe("0");
    expect(formatCount(12345678901234567890n)).toBe("12,345,678,901,234,567,890");
  });
});

describe("the count line's badge", () => {
  /**
   * FAILS ON REVERT: wear "available" whatever the read covered and the green
   * check is back on "from a partial read".
   */
  it("is neutral on a partial read, and never a green check over it", () => {
    const partial = casePageCountBadge(20, { rows_in_window: 312, total_in_window: 4_394, window_complete: false }, false);
    expect(partial.status).toBe("partial");
    expect(partial.label).toContain("from a partial read");
    expect(statusPresentation(partial.status).tone).toBe("neutral");
    expect(statusPresentation(partial.status).symbol).not.toBe("✓");
  });

  it("is a check on a whole read, and says a list being refreshed is stale", () => {
    expect(casePageCountBadge(20, { rows_in_window: 312, window_complete: true }, false).status).toBe("available");
    expect(casePageCountBadge(20, { rows_in_window: 312, window_complete: false }, true).status).toBe("stale");
    expect(casePageCountBadge(3, { window_complete: false }, false).status).toBe("available");
  });
});

describe("the outcome chip", () => {
  it("says what a one-off check is instead of an unexplained Screened", () => {
    const html = renderToStaticMarkup(<Outcome value="screened" />);
    expect(html).toContain(">Checked only<");
    expect(html).toContain('title="Judged by a one-off check.');
    expect(html).not.toContain(">Screened<");
  });

  it("explains every chip it can draw", () => {
    for (const chip of Object.values(OUTCOME_CHIPS)) expect(chip.meaning.length).toBeGreaterThan(10);
    expect(renderToStaticMarkup(<Outcome value="something_new" />)).toContain(">Outcome unknown<");
  });
});

describe("a control named in the plural", () => {
  it("takes are, in the host's sentence and in the page's own", () => {
    expect(agreeWithControls("Response controls is blocking, and that was verified on this host."))
      .toBe("Response controls are blocking, and that was verified on this host.");
    expect(agreeWithControls("Host visibility is watching.")).toBe("Host visibility is watching.");
    const layer = {
      id: "response_controls",
      capability_ids: ["response_controls"],
      label: "Response controls",
      claim_state: "not_covered" as const,
      effective_mode: "disabled" as const,
      desired_mode: "disabled" as const,
      disposition: "not_enabled" as const,
    };
    expect(dispositionReason(layer)).toBe("Response controls have not been turned on yet. Nothing is wrong.");
  });
});

describe("who is signed in", () => {
  /**
   * A change is "recorded under your name", and the page never showed the
   * name. The badge names it.
   */
  it("names the signed-in person, and says only Signed in about a name it cannot print", () => {
    expect(signedInLabel("alice")).toBe("Signed in as alice");
    expect(signedInLabel(null)).toBe("Signed in");
    expect(signedInLabel("  ")).toBe("Signed in");
    expect(signedInLabel("x".repeat(65))).toBe("Signed in");
    expect(signedInLabel("bad\u0007name")).toBe("Signed in");
  });
});
