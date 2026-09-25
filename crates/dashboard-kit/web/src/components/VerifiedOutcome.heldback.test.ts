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

  /**
   * THE DEFECT THIS PINS: a choice a PERSON made in chat reached the plain
   * view credited to automation. The executor writes "ignored by operator",
   * "dismissed by operator" and "rejected by operator <name>", and the words
   * for "ignored" and "dismissed" said the automatic review had decided.
   *
   * FAILS ON REVERT: drop the check for a person and the first two read
   * "the automatic review decided it was not worth acting on".
   */
  it("credits a person's choice to the person, not to the automatic review", () => {
    for (const summary of [
      "Executor result: ignored by operator",
      "Executor result: dismissed by operator",
      "Executor result: rejected by operator Maria",
    ]) {
      const reason = heldBackReason(outcome, withAttempt(attempt(summary)));
      expect(reason, summary).toBe("a person chose not to act on it.");
      expect(reason, summary).not.toContain("automatic");
      // A person's name is not the reason and is not repeated.
      expect(reason, summary).not.toContain("Maria");
    }
    // The generic words, with no person named, still mean the review.
    expect(heldBackReason(outcome, withAttempt(attempt("Executor result: ignored")))).toBe(
      "the automatic review decided it was not worth acting on.",
    );
  });

  /**
   * THE DEFECT THIS PINS: the executor's own reasons name a skill by its id
   * and print the model's raw confidence, and they reached the plain view as
   * "kill-process skill not available." and "AI did not recommend
   * auto-execution (0.42).". Each family has plain words of its own.
   *
   * FAILS ON REVERT: drop the families and these lines print the executor's
   * tokens.
   */
  it("says in plain words what each of the executor's own reasons means", () => {
    const cases: [string, string][] = [
      ["Executor result: skipped: kill-process skill not available", "this response is not switched on here."],
      ["Executor result: skipped: suspend-user-sudo skill not available", "this response is not switched on here."],
      ["Executor result: skipped: skill 'block-container' not in allowed_skills", "this response is not switched on here."],
      ["Executor result: skipped: responder disabled", "this response is not switched on here."],
      ["Executor result: skipped: responder disabled or skill not allowed", "this response is not switched on here."],
      ["Executor result: skipped: no block skill available for 203.0.113.7", "this response is not switched on here."],
      ["Executor result: skipped: AI did not recommend auto-execution (0.42)", "the review did not recommend acting automatically."],
      ["Executor result: skipped: AI did not recommend auto-execution (no trust rule)", "the review did not recommend acting automatically."],
      ["Executor result: skipped: confidence 0.61 below threshold 0.80", "the review was not confident enough to act automatically."],
      ["Executor result: skipped: already blocked", "it was already blocked."],
      ["Executor result: skipped: circuit breaker tripped (blocks this hour exceed 50)", "too many blocks in the last hour."],
      ["Executor result: skipped: 203.0.113.7 is in operator trusted_ips allowlist", "it matched your allowlist."],
      ["Executor result: skipped: target allowlisted", "it matched your allowlist."],
    ];
    for (const [summary, reason] of cases) {
      expect(heldBackReason(outcome, withAttempt(attempt(summary))), summary).toBe(reason);
    }
  });

  /**
   * THE RULE THIS PINS: a reason is shown as it is only when it reads as
   * words. A hyphenated id, a camel-case id or a bare number in brackets is
   * a token, and gives way to the plain sentence.
   *
   * FAILS ON REVERT: drop those three checks and each line below is printed.
   */
  it("gives way to plain words over an id or a raw score it has no words for", () => {
    for (const summary of [
      "Executor result: skipped: gate-token mismatch for this address",
      "Executor result: refused: the reply-router could not place it",
      "Executor result: skipped: AI router emitted BlockIp on invalid",
      "Executor result: skipped: score too low (0.37)",
    ]) {
      const reason = heldBackReason(outcome, withAttempt(attempt(summary)));
      expect(reason, summary).toBe("it was decided, and then not carried out.");
    }
    // A reason that reads as words is still shown as it is.
    expect(heldBackReason(outcome, withAttempt(attempt("Executor result: skipped: 10.0.0.5 is an active operator session")))).toBe(
      "10.0.0.5 is an active operator session.",
    );
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
