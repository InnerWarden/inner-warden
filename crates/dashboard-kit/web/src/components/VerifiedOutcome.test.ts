import { describe, expect, it } from "vitest";
import { parseUnifiedCase } from "../api/cases";
import { verifiedOutcomePresentation } from "./VerifiedOutcome";
import caseAgentHost from "../../tests/fixtures/enterprise/case-agent-host-001.json";
import caseFutureVerification from "../../tests/fixtures/enterprise/case-future-verification-003.json";

const fixture = (name: "case-agent-host-001" | "case-future-verification-003") => parseUnifiedCase(name === "case-agent-host-001" ? caseAgentHost : caseFutureVerification);

describe("verified outcome presentation", () => {
  it("accepts a current matching runtime verification", () => {
    const value = fixture("case-agent-host-001");
    const presentation = verifiedOutcomePresentation(value.verified_outcomes[0], value.timeline, "2026-07-18T12:00:00Z");
    expect(presentation.trusted).toBe(true);
    expect(presentation.label).toBe("Verified pre-execution block");
  });

  it("withholds a future and stale containment claim", () => {
    const value = fixture("case-future-verification-003");
    const presentation = verifiedOutcomePresentation(value.verified_outcomes[0], value.timeline, "2026-07-18T12:00:00Z");
    expect(presentation.trusted).toBe(false);
    expect(presentation.status).toBe("unknown");
    expect(presentation.label).toBe("Outcome claim withheld");
  });
});
