import { describe, expect, it } from "vitest";
import { parseCaseListPage, parseUnifiedCase } from "./cases";
import caseAgentHost from "../../tests/fixtures/enterprise/case-agent-host-001.json";
import caseContextOnly from "../../tests/fixtures/enterprise/case-context-only-002.json";
import caseFutureVerification from "../../tests/fixtures/enterprise/case-future-verification-003.json";
import caseMissingEvidence from "../../tests/fixtures/enterprise/case-missing-evidence-004.json";
import casesPageOne from "../../tests/fixtures/enterprise/cases-page-1.json";
import casesPageTwo from "../../tests/fixtures/enterprise/cases-page-2.json";

const at = "2026-07-18T12:00:00Z";
const source = {
  id: "fixture-source",
  kind: "kernel_state",
  authority: "canonical",
  version: "1",
  completeness: "complete",
  limitations: [],
};
const evidence = {
  id: "fixture-evidence",
  kind: "runtime_verification",
  source,
  observed_at: at,
  integrity: "verified",
  redaction: [],
  freshness: { observed_at: at, budget_seconds: 60, state: "fresh", age_seconds: 0 },
};
const scope = {
  id: "host:fixture",
  kind: "host",
  display_name: "Fixture host",
  verification: "host_verified",
  evidence: [evidence],
};
const summary = {
  id: "case-1",
  title: "Fixture case",
  severity: "high",
  status: "needs_review",
  scope: [scope],
  latest_event_at: at,
  outcome: "unknown",
};

describe("C0 case projections", () => {
  it("parses only a bounded cursor page", () => {
    const page = parseCaseListPage({
      schema_version: "innerwarden.dashboard.v1",
      generated_at: at,
      items: [summary],
      next_cursor: "next-opaque-cursor",
    }, 1);

    expect(page.items).toHaveLength(1);
    expect(page.next_cursor).toBe("next-opaque-cursor");
    expect(() => parseCaseListPage({ ...page, items: [summary, { ...summary, id: "case-2" }] }, 1)).toThrow(/bounded array/);
  });

  it("does not derive a verified outcome from workflow status or decision text", () => {
    const parsed = parseUnifiedCase({
      ...summary,
      status: "contained",
      schema_version: "innerwarden.dashboard.v1",
      identity: { subject_ids: ["agent:fixture"], confidence: "declared", evidence: [] },
      recurrence: { first_seen_at: at, last_seen_at: at, occurrences: "1", state: "single" },
      timeline: [{
        id: "decision-1",
        event_type: "policy_decision",
        observed_at: at,
        recorded_at: at,
        authority: "local_model",
        mode: "enforce",
        summary: "Deny verdict recommended by the model",
        relationship: "contextual",
        source_refs: [],
      }],
      evidence: [],
      feedback: [],
      verified_outcomes: [],
    });

    expect(parsed.status).toBe("contained");
    expect(parsed.verified_outcomes).toEqual([]);
    expect(parsed.outcome).toBe("unknown");
  });

  it("rejects fields outside the frozen C0 payload", () => {
    expect(() => parseCaseListPage({
      schema_version: "innerwarden.dashboard.v1",
      generated_at: at,
      items: [],
      next_cursor: null,
      total: 0,
    })).toThrow(/unexpected field total/);
  });

  it("keeps every checked-in browser fixture inside the frozen C0 shape", () => {
    expect(parseCaseListPage(casesPageOne, 20).items).toHaveLength(2);
    expect(parseCaseListPage(casesPageTwo, 20).next_cursor).toBeNull();
    for (const [name, fixture] of [
      ["case-agent-host-001", caseAgentHost],
      ["case-context-only-002", caseContextOnly],
      ["case-future-verification-003", caseFutureVerification],
      ["case-missing-evidence-004", caseMissingEvidence],
    ] as const) {
      expect(parseUnifiedCase(fixture).id).toBe(name);
    }
  });
});

describe("server-side case window (paid API opt-in)", () => {
  const legacy = {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: "2026-08-06T12:00:00Z",
    items: [],
    next_cursor: null,
  };

  // REGRESSION ANCHOR. The free server sends none of the windowed fields, and
  // the screen must keep working against it unchanged: absent means absent,
  // never a default, never an invented total.
  it("parses the legacy body exactly as before, with no windowed fields", () => {
    const page = parseCaseListPage(legacy);
    expect(page.window).toBeUndefined();
    expect(page.total_in_window).toBeUndefined();
    expect(page.window_complete).toBeUndefined();
  });

  it("parses the windowed trio when the paid server sends it", () => {
    const page = parseCaseListPage({ ...legacy, window: "7d", total_in_window: 312, window_complete: true });
    expect(page.window).toBe("7d");
    expect(page.total_in_window).toBe(312);
    expect(page.window_complete).toBe(true);
  });

  it("rejects a malformed windowed payload loudly", () => {
    expect(() => parseCaseListPage({ ...legacy, window: "fortnight" })).toThrow("unknown window");
    expect(() => parseCaseListPage({ ...legacy, total_in_window: -1 })).toThrow("non-negative");
    expect(() => parseCaseListPage({ ...legacy, window_complete: "yes" })).toThrow("not a boolean");
  });
});
