import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { parseUnifiedCase, type CaseEvent } from "../api/cases";
import { CaseTimeline, relationshipLegend, rootEventId } from "./CaseTimeline";
import heldBackCase from "../../tests/fixtures/enterprise/case-held-back-005.json";

/**
 * THE DEFECT THIS PINS
 *
 * The host marks a case's own incident "unknown relationship" on every
 * incident case, because how the event a case starts from relates to "the
 * events next to it" is not a question. The timeline printed a "? Unknown
 * relationship" badge on step one of every incident case and, for that one
 * event, the legend explaining what unknown means.
 *
 * FAILS ON REVERT: count the root in the legend again and this case, whose
 * other events are all causal, grows the unknown legend back.
 */

const value = parseUnifiedCase(heldBackCase);

describe("the event a case starts from", () => {
  it("is its first incident", () => {
    expect(rootEventId(value.timeline)).toBe(value.timeline[0].id);
    expect(rootEventId(value.timeline.filter((event) => event.event_type !== "incident"))).toBeUndefined();
  });

  it("is left out of the legend, which a case of causal steps then does not need", () => {
    expect(value.timeline[0].relationship).toBe("unknown");
    expect(relationshipLegend(value.timeline)).toEqual([]);
    const html = renderToStaticMarkup(<CaseTimeline events={value.timeline} />);
    expect(html).not.toContain("Unknown relationship");
  });

  it("still explains an unknown step that is not where the case starts", () => {
    const later: CaseEvent = { ...value.timeline[1], id: "event:later", relationship: "unknown" };
    const timeline = [...value.timeline, later];
    expect(relationshipLegend(timeline).some((line) => line.startsWith("Unknown relationship:"))).toBe(true);
    expect(renderToStaticMarkup(<CaseTimeline events={timeline} />)).toContain("Unknown relationship");
  });

  it("keeps a badge on the root when the host did relate it", () => {
    const related = value.timeline.map((event, index) => (index === 0 ? { ...event, relationship: "causal" as const } : event));
    expect(renderToStaticMarkup(<CaseTimeline events={related} />).match(/>Causal</g)?.length).toBe(value.timeline.length);
  });
});
