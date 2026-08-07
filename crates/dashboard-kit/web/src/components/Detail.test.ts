import { describe, expect, it } from "vitest";
import { detailRowLabels } from "./Detail";

/**
 * The free product's dig-in path. Open one recorded action and the dialog has
 * to answer: what happened, when, what the system did, whether it was actually
 * stopped, and where it came from.
 */
describe("the decision dialog answers the operator's questions in order", () => {
  it("leads with the verdict and whether it was actually stopped", () => {
    const labels = detailRowLabels({ when: true, session: true, mode: true });
    expect(labels.slice(0, 2)).toEqual(["Verdict", "Execution outcome"]);
  });

  it("puts when and where above who decided and how risky", () => {
    const labels = detailRowLabels({ when: true, session: true, mode: true });
    expect(labels.indexOf("Recorded")).toBeLessThan(labels.indexOf("Decision source"));
    expect(labels.indexOf("Session")).toBeLessThan(labels.indexOf("Decision source"));
    expect(labels.indexOf("Session")).toBeLessThan(labels.indexOf("Risk score"));
  });

  /**
   * "Sequence #12" counted our own rows, sat above the timestamp, and is
   * printed on the list this dialog opens from.
   */
  it("does not count its own records at the user", () => {
    for (const when of [true, false]) {
      for (const session of [true, false]) {
        for (const mode of [true, false]) {
          expect(detailRowLabels({ when, session, mode })).not.toContain("Sequence");
        }
      }
    }
  });

  it("omits a row it has no value for rather than printing an empty one", () => {
    expect(detailRowLabels({ when: false, session: false, mode: false }))
      .toEqual(["Verdict", "Execution outcome", "Decision source", "Risk score"]);
  });

  it("keeps every label unique, so a row cannot render twice", () => {
    const labels = detailRowLabels({ when: true, session: true, mode: true });
    expect(new Set(labels).size).toBe(labels.length);
  });
});
