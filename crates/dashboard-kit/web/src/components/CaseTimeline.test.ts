import { describe, expect, it } from "vitest";
import type { CaseEvent } from "../api/cases";
import { recordingLag, relationshipLegend } from "./CaseTimeline";

type Relationship = CaseEvent["relationship"];

function events(...relationships: Relationship[]): Pick<CaseEvent, "relationship">[] {
  return relationships.map((relationship) => ({ relationship }));
}

/**
 * The same sentence, five times down one column.
 *
 * Every contextual event carried its own amber box saying context is not
 * causation, and every unknown event carried its own grey one, word for word,
 * beside a badge that already said "Contextual" or "Unknown relationship". The
 * honesty is unchanged; it is stated once for the whole list.
 */
describe("relationship meanings are a legend, not a per-event banner", () => {
  it("says the contextual meaning once however many contextual events there are", () => {
    const one = relationshipLegend(events("contextual"));
    const many = relationshipLegend(events("contextual", "contextual", "causal", "contextual"));
    expect(many).toEqual(one);
    expect(one.filter((line) => line.startsWith("Contextual:"))).toHaveLength(1);
  });

  it("says the unknown meaning once however many unknown events there are", () => {
    const many = relationshipLegend(events("unknown", "unknown", "unknown"));
    expect(many.filter((line) => line.startsWith("Unknown relationship:"))).toHaveLength(1);
  });

  it("keeps the order-is-not-causation rule whenever anything is less than causal", () => {
    for (const relationship of ["contextual", "unknown"] as Relationship[]) {
      expect(relationshipLegend(events(relationship)).some((line) => line.includes("never makes one event the cause"))).toBe(true);
    }
  });

  /**
   * A case whose every event is causal has nothing to explain, so it gets no
   * legend at all rather than a paragraph about states it does not contain.
   */
  it("renders nothing when every event is causal or strongly supported", () => {
    expect(relationshipLegend(events("causal", "strongly_supported", "causal"))).toEqual([]);
    expect(relationshipLegend([])).toEqual([]);
  });
});

describe("the moment a source wrote an event down", () => {
  // Bookkeeping when it agrees with the observation, and a real fact about a
  // lagging source when it does not. It used to render on every event either way.
  it("is hidden when it matches the observation", () => {
    expect(recordingLag({ observed_at: "2026-08-07T10:00:00Z", recorded_at: "2026-08-07T10:00:00Z" })).toBe(false);
  });

  it("is shown when the source recorded it later than it happened", () => {
    expect(recordingLag({ observed_at: "2026-08-07T10:00:00Z", recorded_at: "2026-08-07T10:04:00Z" })).toBe(true);
  });
});
