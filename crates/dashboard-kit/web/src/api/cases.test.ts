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
// The count is flat on a SUMMARY and nested under `recurrence` on a DETAIL, so
// a detail payload is built from `detailShape` and never by spreading this.
const summary = {
  id: "case-1",
  title: "Fixture case",
  severity: "high",
  status: "needs_review",
  scope: [scope],
  latest_event_at: at,
  recurrence_occurrences: "1",
  outcome: "unknown",
};

/** The summary minus the fields that only exist on a summary. */
function detailShape() {
  const { recurrence_occurrences: _flatCount, ...rest } = summary;
  return rest;
}

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
      ...detailShape(),
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

/**
 * `rows_in_window` is the row count after the recurrence fold, the "of M" the
 * pages walk; `total_in_window` counts the cases behind those rows. The paid
 * server sends the row count only when the list request asks for it, and the
 * parser is exact-key, so a bundle that did not know the key would reject the
 * whole page.
 */
describe("the row total beside the case total", () => {
  const legacy = {
    schema_version: "innerwarden.dashboard.v1",
    generated_at: "2026-09-24T08:00:00Z",
    items: [],
    next_cursor: null,
  };

  it("keeps the row total apart from the case total", () => {
    const page = parseCaseListPage({ ...legacy, window: "7d", total_in_window: 4_394, window_complete: true, rows_in_window: 312 });
    expect(page.rows_in_window).toBe(312);
    expect(page.total_in_window).toBe(4_394);
  });

  it("accepts the row total without a window, as the server sends it", () => {
    const page = parseCaseListPage({ ...legacy, rows_in_window: 0 });
    expect(page.rows_in_window).toBe(0);
    expect(page.total_in_window).toBeUndefined();
  });

  it("leaves it absent when the server did not send it, never zero", () => {
    const page = parseCaseListPage({ ...legacy, window: "7d", total_in_window: 4_394, window_complete: true });
    expect(page.rows_in_window).toBeUndefined();
    expect("rows_in_window" in page).toBe(false);
  });

  it("rejects a row total that is not a count, naming the field", () => {
    for (const value of [-1, 1.5, "312", null, Number.NaN]) {
      expect(() => parseCaseListPage({ ...legacy, rows_in_window: value })).toThrow("cases.rows_in_window: not a non-negative integer");
    }
  });

  /**
   * The rows on a page are some of the rows that match, so a row total below
   * the page's own item count is a count that cannot be true, and would print
   * "2 rows on this page of 1". It fails as a contract fault, naming why.
   */
  it("rejects a row total smaller than the page it came with", () => {
    expect(casesPageOne.items.length).toBe(2);
    expect(() => parseCaseListPage({ ...casesPageOne, rows_in_window: 1 }))
      .toThrow("cases.rows_in_window: fewer rows than this page holds");
    // The boundary: exactly the page is the last page of a list that fits on one.
    expect(parseCaseListPage({ ...casesPageOne, rows_in_window: 2 }).rows_in_window).toBe(2);
  });

  /**
   * The fold only merges cases into rows, so there are never more rows than the
   * cases behind them. A row total above the case total is a count that cannot
   * be true, and would print "20 rows on this page of 5 · 2 cases".
   */
  it("rejects more rows than the cases they were folded from", () => {
    expect(() => parseCaseListPage({ ...legacy, window: "7d", total_in_window: 2, window_complete: true, rows_in_window: 5 }))
      .toThrow("cases.rows_in_window: more rows than the cases they were folded from");
    // Equal is a window where nothing recurred: every case is its own row.
    expect(parseCaseListPage({ ...legacy, window: "7d", total_in_window: 5, window_complete: true, rows_in_window: 5 }).rows_in_window).toBe(5);
    // With no case total sent there is nothing to hold it against.
    expect(parseCaseListPage({ ...legacy, rows_in_window: 5 }).rows_in_window).toBe(5);
  });

  /**
   * JSON can carry -0, which is an integer and not below zero, so it passes
   * every check above and used to print "of -0". The parser hands on 0.
   */
  it("reads a JSON -0 as zero for both totals", () => {
    const page = parseCaseListPage(JSON.parse(
      '{"schema_version":"innerwarden.dashboard.v1","generated_at":"2026-09-24T08:00:00Z","items":[],"next_cursor":null,'
      + '"window":"7d","total_in_window":-0,"window_complete":true,"rows_in_window":-0}',
    ));
    expect(Object.is(page.rows_in_window, 0)).toBe(true);
    expect(Object.is(page.total_in_window, 0)).toBe(true);
  });
});

describe("the connections block", () => {
  const withConnections = (connections: unknown) =>
    JSON.parse(JSON.stringify({ ...caseAgentHost, connections }));

  const link = {
    from: "bash",
    from_kind: "process",
    relation: "connected out to",
    to: "203.0.113.9",
    to_kind: "address",
    observed_at: "2026-07-18T11:00:00Z",
    involves_this_case: true,
  };

  it("carries the links the host phrased", () => {
    const parsed = parseUnifiedCase(withConnections({ links: [link], total_recorded: 1, absence_reason: null }));
    expect(parsed.connections.links).toHaveLength(1);
    expect(parsed.connections.links[0].relation).toBe("connected out to");
    expect(parsed.connections.total_recorded).toBe(1);
  });

  /**
   * THE ONE STATE THAT MUST NEVER RENDER.
   *
   * No links and no reason is a blank area, and a blank area can only be read
   * as "nothing was connected". The connection store evicts under a size cap,
   * so that is a claim it cannot support. A producer that sends it has a bug,
   * and it fails here rather than on a customer's screen.
   */
  it("refuses an empty block that gives no reason", () => {
    expect(() => parseUnifiedCase(withConnections({ links: [], total_recorded: 0, absence_reason: null })))
      .toThrow(/nothing happened/);
  });

  it("accepts an empty block that says why", () => {
    const parsed = parseUnifiedCase(withConnections({
      links: [],
      total_recorded: 0,
      absence_reason: "No connections were recorded around this one.",
    }));
    expect(parsed.connections.links).toEqual([]);
    expect(parsed.connections.absence_reason).toContain("No connections");
  });

  /**
   * An older host has no such field. That is not a malformed payload, and
   * failing the whole case over it would take the page down on the very
   * version that most needs to be readable.
   */
  it("treats an absent block as an unreported one, not a broken one", () => {
    const payload = JSON.parse(JSON.stringify(caseAgentHost));
    delete payload.connections;
    const parsed = parseUnifiedCase(payload);
    expect(parsed.connections.links).toEqual([]);
    expect(parsed.connections.absence_reason).toBeTruthy();
  });

  it("rejects a malformed block instead of degrading it", () => {
    expect(() => parseUnifiedCase(withConnections({ links: [link], total_recorded: -1, absence_reason: null })))
      .toThrow(/total_recorded/);
    expect(() => parseUnifiedCase(withConnections({ links: [{ ...link, relation: "" }], total_recorded: 1, absence_reason: null })))
      .toThrow();
    expect(() => parseUnifiedCase(withConnections({ links: [link], total_recorded: 1, absence_reason: null, extra: 1 })))
      .toThrow();
  });
});

describe("the evidence badge", () => {
  /**
   * The badge said "Partial evidence" on every row of the production capture,
   * and it could not have said anything else: its predicate ORed over three
   * clauses the paid adapter makes permanently true. The host now decides it.
   */
  it("carries the host's verdict, both ways", () => {
    for (const value of [true, false]) {
      const payload = JSON.parse(JSON.stringify({ ...caseAgentHost, has_gap: value }));
      expect(parseUnifiedCase(payload).has_gap).toBe(value);
    }
  });

  it("treats an absent verdict as not-decided, not as a broken payload", () => {
    const payload = JSON.parse(JSON.stringify(caseAgentHost));
    expect(parseUnifiedCase(payload).has_gap).toBeUndefined();
  });

  it("refuses a verdict that is not a boolean", () => {
    const payload = JSON.parse(JSON.stringify({ ...caseAgentHost, has_gap: "yes" }));
    expect(() => parseUnifiedCase(payload)).toThrow();
  });
});
