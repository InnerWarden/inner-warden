import { describe, expect, it } from "vitest";
import { parseUnifiedCase, type VerifiedOutcome } from "../api/cases";
import { verifiedOutcomePresentation } from "./VerifiedOutcome";
import caseAgentHost from "../../tests/fixtures/enterprise/case-agent-host-001.json";
import caseFutureVerification from "../../tests/fixtures/enterprise/case-future-verification-003.json";

const fixture = (name: "case-agent-host-001" | "case-future-verification-003") => parseUnifiedCase(name === "case-agent-host-001" ? caseAgentHost : caseFutureVerification);

describe("verified outcome presentation", () => {
  it("reports an independently checked block, and says who checked", () => {
    const value = fixture("case-agent-host-001");
    const presentation = verifiedOutcomePresentation(value.verified_outcomes[0], value.timeline, "2026-07-18T12:00:00Z");
    expect(presentation.trusted).toBe(true);
    expect(presentation.independentlyChecked).toBe(true);
    expect(presentation.label).toBe("Blocked before it ran, checked");
  });

  it("reports nothing when the record does not hold together", () => {
    const value = fixture("case-future-verification-003");
    const presentation = verifiedOutcomePresentation(value.verified_outcomes[0], value.timeline, "2026-07-18T12:00:00Z");
    expect(presentation.trusted).toBe(false);
    expect(presentation.independentlyChecked).toBe(false);
    expect(presentation.status).toBe("unknown");
    expect(presentation.label).toBe("No outcome reported");
  });

  /**
   * THE REGRESSION TEST.
   *
   * This is the record every Community guard block produces: a real in-path
   * refusal, no enforcement attempt id (the refusal IS the record), and
   * evidence the producer never claimed to have independently verified.
   *
   * The old component ran its own predicate over exactly those three fields and
   * returned "Outcome claim withheld", while the Rust header said "Blocked
   * Before Execution" about the same record on the same screen.
   *
   * It has to render as a reported block that nobody else checked. Withholding
   * it is a false negative over a guard that did its job; calling it verified
   * is a claim nothing supports.
   */
  it("reports an in-path guard refusal that nothing else witnessed", () => {
    const value = fixture("case-agent-host-001");
    const inPath: VerifiedOutcome = {
      ...value.verified_outcomes[0],
      enforcement_attempt_id: null,
      evidence: value.verified_outcomes[0].evidence.map((entry) => ({ ...entry, integrity: "unverified" as const })),
      trust: "recorded",
      trust_explanation: "The guard refused this in line, and recorded it as it happened.",
    };
    const presentation = verifiedOutcomePresentation(inPath, value.timeline, "2026-07-18T12:00:00Z");
    expect(presentation.trusted).toBe(true);
    expect(presentation.independentlyChecked).toBe(false);
    expect(presentation.status).toBe("blocked_before_execution");
    expect(presentation.label).toBe("Blocked before it ran");
    expect(presentation.explanation).toBe(inPath.trust_explanation);
  });

  /**
   * The component must RENDER the verdict, never re-derive one.
   *
   * Every field the old predicate consulted is set here to something it would
   * have rejected: a dangling attempt id, unverified evidence, a verification
   * time in the future, an empty scope. If any of that still moves the answer,
   * a second opinion has survived in TypeScript and the two sides can drift
   * apart again.
   */
  it("ignores every field the old predicate used to consult", () => {
    const value = fixture("case-agent-host-001");
    const hostile: VerifiedOutcome = {
      ...value.verified_outcomes[0],
      enforcement_attempt_id: "resp-15384-does-not-exist",
      verification_status: "unknown",
      verifier: null,
      verified_at: "2099-01-01T00:00:00Z",
      effective_scope: [],
      evidence: [],
      trust: "proven",
      trust_explanation: "decided by the backend",
    };
    const presentation = verifiedOutcomePresentation(hostile, value.timeline, "2026-07-18T12:00:00Z");
    expect(presentation.trusted).toBe(true);
    expect(presentation.independentlyChecked).toBe(true);
    expect(presentation.explanation).toBe("decided by the backend");
  });

  /**
   * The words carry the distinction, not only the badge, because a badge is the
   * first thing a compact layout drops.
   */
  it("says something different for each of the three verdicts", () => {
    const value = fixture("case-agent-host-001");
    const base = value.verified_outcomes[0];
    const labels = (["proven", "recorded", "unproven"] as const).map((trust) =>
      verifiedOutcomePresentation({ ...base, trust }, value.timeline, "2026-07-18T12:00:00Z").label);
    expect(new Set(labels).size).toBe(3);
  });
});

describe("the payload contract", () => {
  it("refuses a case whose outcome carries no verdict", () => {
    const missing = JSON.parse(JSON.stringify(caseAgentHost));
    delete missing.verified_outcomes[0].trust;
    expect(() => parseUnifiedCase(missing)).toThrow();
  });

  it("refuses a verdict that is not one of the three", () => {
    const bogus = JSON.parse(JSON.stringify(caseAgentHost));
    bogus.verified_outcomes[0].trust = "verified";
    expect(() => parseUnifiedCase(bogus)).toThrow();
  });
});
