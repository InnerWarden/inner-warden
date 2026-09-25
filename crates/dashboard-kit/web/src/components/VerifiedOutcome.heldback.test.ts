import { describe, expect, it } from "vitest";

import { parseUnifiedCase, type CaseEvent, type VerifiedOutcome } from "../api/cases";
import { heldBackReason, verifiedOutcomePresentation } from "./VerifiedOutcome";
import heldBackCase from "../../tests/fixtures/enterprise/case-held-back-005.json";

/**
 * THE DEFECT THIS PINS
 *
 * A block the executor skipped (the address belongs to a cloud provider) or
 * refused (it is the management network) is lifecycle `rejected` with
 * outcome `not_observed`. The panel said "Never happened / There is no
 * record of this happening" over a timeline whose next step read "Executor
 * result: skipped: ... is in cloud provider safelist". It now says "Held
 * back", and why, from the lifecycle already on the wire.
 */

const value = parseUnifiedCase(heldBackCase);
const outcome = value.verified_outcomes[0];
const now = "2026-09-25T12:00:00Z";

function attempt(summary: string, overrides: Partial<CaseEvent> = {}): CaseEvent {
  const own = value.timeline.find((event) => event.event_type === "enforcement_attempt") as CaseEvent;
  return { ...own, summary, ...overrides };
}

function withAttempt(event: CaseEvent): CaseEvent[] {
  return value.timeline.map((entry) => (entry.event_type === "enforcement_attempt" ? event : entry));
}

describe("an action decided and then not carried out", () => {
  /**
   * FAILS ON REVERT: drop the rejected-lifecycle branch and the label is
   * "Never happened" again.
   */
  it("says Held back, and gives the executor's reason", () => {
    const presentation = verifiedOutcomePresentation(outcome, value.timeline, now);
    expect(presentation.label).toBe("Held back");
    expect(presentation.meaning).toBe("Held back: 198.51.100.23 is in cloud provider safelist (Google Cloud).");
    expect(presentation.status).toBe("not_observed");
    expect(presentation.trusted).toBe(true);
    expect(`${presentation.label} ${presentation.meaning}`).not.toContain("Never happened");
    expect(presentation.meaning).not.toContain("no record");
  });

  it("gives a refusal's reason too", () => {
    const refused = attempt("Executor result: refused: 203.0.113.7 is inside the protected management path 203.0.113.0/24. Blocking it would cut the operator off from the box");
    expect(heldBackReason(outcome, withAttempt(refused))).toBe(
      "203.0.113.7 is inside the protected management path 203.0.113.0/24. Blocking it would cut the operator off from the box.",
    );
  });

  it("says in its own words why a result that carries no reason held it back", () => {
    const cases: [string, string][] = [
      ["Executor result: rate-limited: 203.0.113.7 (>20 blocks/min)", "too many blocks in the last minute."],
      ["Executor result: dismissed", "the automatic review decided it was not worth acting on."],
      ["Executor result: suppressed by allowlist", "it matched your allowlist."],
      ["Executor result: redecided", "a later decision replaced it."],
    ];
    for (const [summary, reason] of cases) expect(heldBackReason(outcome, withAttempt(attempt(summary)))).toBe(reason);
  });

  it("names watch mode for a rehearsal, whatever the line says", () => {
    const rehearsal = attempt("Executor result: Blocked 203.0.113.7 via XDP", { mode: "rehearse" });
    expect(heldBackReason(outcome, withAttempt(rehearsal))).toBe("this server is in watch mode, so nothing was enforced.");
  });

  /**
   * The plain view never prints the executor's tokens. A reason carrying an
   * identifier, a digest or markers gives way to a plain sentence; the whole
   * line is still on the timeline.
   */
  it("never prints the executor's tokens", () => {
    for (const summary of [
      "Executor result: skipped: dry_run is set",
      "Executor result: refused: target=203.0.113.7 policy=protected",
      "Executor result: skipped: 6591615a6feb7908559ac0f9 matched",
      "Executor result: something new the kit has never seen",
    ]) {
      const reason = heldBackReason(outcome, withAttempt(attempt(summary)));
      expect(reason, summary).toBe("it was decided, and then not carried out.");
    }
  });

  it("reads the event whose evidence is the outcome's own when there are several", () => {
    const other: CaseEvent = {
      ...attempt("Executor result: rate-limited: 203.0.113.9"),
      id: "event:other-attempt",
      source_refs: [{ ...value.timeline[0].source_refs[0], id: "event:other-decision" }],
    };
    const timeline = [...withAttempt(attempt("Executor result: skipped: 198.51.100.23 is in cloud provider safelist (Google Cloud)")), other];
    expect(heldBackReason(outcome, timeline)).toBe("198.51.100.23 is in cloud provider safelist (Google Cloud).");
    // Several, and none of them the outcome's own: nothing to say.
    const stranger: VerifiedOutcome = { ...outcome, evidence: [{ ...outcome.evidence[0], id: "event:unrelated" }] };
    expect(heldBackReason(stranger, timeline)).toBeUndefined();
  });

  it("keeps the outcome's own words when nothing on the case was held back", () => {
    const plain = value.timeline.map((event) => ({ ...event, action_lifecycle: null }));
    const presentation = verifiedOutcomePresentation(outcome, plain, now);
    expect(presentation.label).toBe("Never happened");
  });

  it("leaves an action waiting for a person as waiting", () => {
    const pending = value.timeline.map((event) => (event.event_type === "enforcement_attempt" ? { ...event, action_lifecycle: "pending" } : event));
    expect(verifiedOutcomePresentation(outcome, pending, now).label).toBe("Waiting for you");
  });
});
