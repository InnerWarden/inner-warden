import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import type { CapabilityStatus, DashboardBootstrap, DashboardPosture, EvidenceRef, ProtectionLayer, ScopeRef } from "../api/v1";
import { setTechnicalDetail } from "../components/TechnicalDetail";
import { POSTURE_REFRESH_MS } from "../posture/refresh";
import { bootstrapStillBacks, heldAssurance, HOLD_GRACE_MS, Posture, type HeldVerification } from "./Posture";

/**
 * A control the host proved, on a page the reader leaves open.
 *
 * The chips were judged against the consumer's clock, which ticks every
 * second, while the evidence behind them carries a budget of seconds and the
 * page reads the host every few minutes. So a proven control read
 * "Protecting" for half a minute, then "Containing, not proven", and
 * "Protecting" again when the reader pressed Check now. Nothing on the host
 * had changed; the chips had. These pin that a verification lasts as long as
 * the read it was made on, and that the next read decides again.
 */

afterEach(() => setTechnicalDetail(false));

const matrix = {
  id: "innerwarden.assurance-matrix",
  version: "AM-090-v1",
  canonicalization: "YAML-TO-RFC8785-JCS" as const,
  digest: `sha256:${"a".repeat(64)}`,
};

const OBSERVED = "2026-07-18T12:00:00Z";
const GENERATED = "2026-07-18T12:00:01Z";

const evidence: EvidenceRef = {
  id: "ev-1",
  kind: "runtime_verification",
  source: { id: "kernel_state", kind: "kernel_state", authority: "canonical", version: "1", completeness: "complete", limitations: [] },
  observed_at: OBSERVED,
  integrity: "verified",
  redaction: [],
  freshness: { observed_at: OBSERVED, budget_seconds: 30, state: "fresh", age_seconds: 1 },
};

const scope: ScopeRef = { id: "host-1", kind: "host", display_name: "pilot host", verification: "host_verified", evidence: [{ ...evidence }] };

const stage = () => ({ state: "yes" as const, evidence: [{ ...evidence }], reason_code: null });
const converged = () => ({ configured: stage(), loaded: stage(), running: stage(), enforcing: stage(), verified_effective: stage() });
const freshness = () => ({ observed_at: OBSERVED, budget_seconds: 30, state: "fresh" as const, age_seconds: 1 });

function capability(): CapabilityStatus {
  return {
    id: "kernel_execution_control",
    tier: "enterprise_core",
    availability: "available",
    entitlement: "valid",
    support: "supported",
    desired_mode: "enforce",
    effective_mode: "enforce",
    convergence: converged(),
    rollout_state: "enforcing",
    health: "healthy",
    scope: [{ ...scope }],
    covered_action_classes: ["process_execution"],
    bypass_classes: [],
    known_uncovered_paths: [],
    freshness: freshness(),
    last_evidence: { ...evidence },
    sources: [],
    claims: [{
      id: "claim-1", statement: "covered executions are blocked", semantic_key: null, status: "verified",
      versions: [{ ...matrix }],
      population: "host-1", environment: "linux",
      observed_at: OBSERVED, reviewed_at: OBSERVED, expires_at: "2026-07-18T13:00:00Z",
      scope: [{ ...scope }], action_classes: ["process_execution"],
      evidence: [{ ...evidence }], limitations: [],
    }],
    reason_code: null,
    summary: "fresh verified enforcement",
  };
}

const bootstrap: DashboardBootstrap = {
  schema_version: "innerwarden.dashboard.v1",
  generated_at: GENERATED,
  edition: "enterprise",
  product_version: "0.16.4",
  community_contract: { id: "CJC-090", version: "CJC-090-v1", canonicalization: "RAW-UTF8-BYTES-SHA256", digest: `sha256:${"d".repeat(64)}` },
  assurance_matrix: matrix,
  authorization_matrix: null,
  platform: { os: "linux", architecture: "x86_64", enterprise_candidate: true, reason_code: null },
  session: { authenticated: true, actor_id: "operator", role: "security_operator", scopes: [] },
  capabilities: [capability()],
  highest_priority_gap: null,
  privacy: { storage: [], redactions: [], egress: [] },
};

function layer(): ProtectionLayer {
  return {
    id: "independent_host_execution",
    label: "Independent host execution",
    capability_ids: ["kernel_execution_control"],
    claim_state: "active",
    disposition: "proven",
    effective_mode: "enforce",
    desired_mode: "enforce",
    effective_scope: [{ ...scope }],
    covered_action_classes: ["process_execution"],
    known_gaps: [],
    freshness: freshness(),
    convergence: converged(),
    evidence: [{ ...evidence }],
  };
}

/** One read of the host: a new object every time, as the shell keeps them. */
function read(): DashboardPosture {
  return { schema_version: "innerwarden.dashboard.v1", generated_at: GENERATED, layers: [layer()], gaps: [] };
}

function chip(posture: DashboardPosture, evaluatedAt: string, current = true, reading: DashboardBootstrap = bootstrap): string {
  const html = renderToStaticMarkup(<Posture bootstrap={reading} posture={posture} current={current} evaluatedAt={evaluatedAt} />);
  // The control's state is said twice: by its segment of the ring and by the
  // badge on its row. The two are one computation, and a read where they
  // disagree fails here whatever the state is.
  const ring = html.match(/<title>[^<:]*: ([^<]*)<\/title>/)?.[1] ?? "";
  const row = html.slice(html.indexOf("<article")).match(/<span class="min-w-0 break-words">([^<]*)<\/span>/)?.[1] ?? "";
  expect(ring).toBe(row);
  return row;
}

describe("a proven control on a page left open", () => {
  it("is proven on the read that proved it", () => {
    expect(chip(read(), GENERATED)).toBe("Protecting");
  });

  /**
   * FAILS ON REVERT: judge every render against the ticking clock alone and
   * the same read reads "Containing, not proven" forty seconds later.
   */
  it("stays proven for the life of that read as the clock passes its budget", () => {
    const snapshot = read();
    expect(chip(snapshot, GENERATED)).toBe("Protecting");
    expect(chip(snapshot, "2026-07-18T12:00:40Z")).toBe("Protecting");
    expect(chip(snapshot, "2026-07-18T12:04:59Z")).toBe("Protecting");
  });

  /**
   * The next read decides from scratch: a host that keeps re-serving the same
   * frozen snapshot is a new read each time, and its evidence is judged by
   * the clock at that read, so a hold never outlives its read.
   */
  it("is decided again on the next read, and demoted there when that read cannot prove it", () => {
    const first = read();
    expect(chip(first, GENERATED)).toBe("Protecting");
    expect(chip(read(), "2026-07-18T12:05:00Z")).toBe("Containing, not proven");
  });

  it("holds nothing on a page whose reading is not current", () => {
    const snapshot = read();
    expect(chip(snapshot, GENERATED)).toBe("Protecting");
    expect(chip(snapshot, "2026-07-18T12:00:40Z", false)).toBe("Refreshing");
  });

  it("holds only what that read verified, never what it did not", () => {
    const held = new WeakMap<DashboardPosture, Map<string, HeldVerification>>();
    const snapshot = read();
    const at = { bootstrap, evaluatedAt: GENERATED };
    const later = { bootstrap, evaluatedAt: "2026-07-18T12:00:40Z" };
    const withheld = { label: "Active claim withheld", status: "degraded", verifiedActive: false };
    expect(heldAssurance(snapshot, layer(), withheld, true, at, held)).toEqual(withheld);
    const verified = { label: "Verified active enforcement", status: "active", verifiedActive: true };
    expect(heldAssurance(snapshot, layer(), verified, true, at, held).verifiedActive).toBe(true);
    expect(heldAssurance(snapshot, layer(), withheld, true, later, held).verifiedActive).toBe(true);
    expect(heldAssurance(snapshot, { ...layer(), id: "another" }, withheld, true, later, held)).toEqual(withheld);
    expect(heldAssurance(read(), layer(), withheld, true, later, held)).toEqual(withheld);
  });

  /**
   * The row under the chips reads the same assurance: the disclosure never
   * says the claim was withheld beside a chip that says it was proven. And
   * a verification held from earlier in the read says when it was made,
   * never a present tense.
   */
  it("tells the chip, the row and the disclosure the same story, and says when it was verified", () => {
    const snapshot = read();
    const first = renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={snapshot} current evaluatedAt={GENERATED} />);
    expect(first).toContain(">Verified active enforcement<");
    const later = renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={snapshot} current evaluatedAt="2026-07-18T12:00:40Z" />);
    expect(later).toContain("Active enforcement verified at ");
    expect(later).not.toContain(">Verified active enforcement<");
    expect(later).not.toContain("Active claim withheld");
    expect(later).not.toContain("Containing, not proven");
  });
});

/**
 * A hold keeps a verification for as long as it could still be true on the
 * read it was made on, and no longer. Each of these FAILS ON REVERT to a hold
 * keyed on the posture object alone: that one kept "Protecting" under a
 * bootstrap withdrawing the capability, two hours past the claim's expiry,
 * and on a read that had stalled.
 */
describe("a held verification", () => {
  /** The same bootstrap, the capability withdrawn: health failed, no claims. */
  function withdrawn(): DashboardBootstrap {
    return {
      ...bootstrap,
      generated_at: "2026-07-18T12:03:00Z",
      capabilities: [{ ...capability(), health: "failed", availability: "degraded", claims: [] }],
    };
  }

  it("ends at a new bootstrap read that withdraws the capability, on the same posture read", () => {
    const snapshot = read();
    expect(chip(snapshot, GENERATED)).toBe("Protecting");
    expect(chip(snapshot, "2026-07-18T12:03:00Z", true, withdrawn())).toBe("Containing, not proven");
    // And a new posture read under that bootstrap decides the same.
    expect(chip(read(), "2026-07-18T12:03:00Z", true, withdrawn())).toBe("Containing, not proven");
  });

  it("survives a new bootstrap read that still backs the control", () => {
    const snapshot = read();
    expect(chip(snapshot, GENERATED)).toBe("Protecting");
    const again = { ...bootstrap, generated_at: "2026-07-18T12:03:00Z", capabilities: [capability()] };
    expect(chip(snapshot, "2026-07-18T12:03:00Z", true, again)).toBe("Protecting");
  });

  it("never outlives the claim's expiry", () => {
    const snapshot = read();
    expect(chip(snapshot, GENERATED)).toBe("Protecting");
    // The claim expires at 13:00; the read is otherwise still being held.
    const shortClaim = { ...bootstrap, capabilities: [{ ...capability(), claims: capability().claims.map((claim) => ({ ...claim, expires_at: "2026-07-18T12:02:00Z" })) }] };
    const early = read();
    expect(chip(early, GENERATED, true, shortClaim)).toBe("Protecting");
    expect(chip(early, "2026-07-18T12:01:59Z", true, shortClaim)).toBe("Protecting");
    expect(chip(early, "2026-07-18T12:02:01Z", true, shortClaim)).toBe("Containing, not proven");
    expect(chip(snapshot, "2026-07-18T15:00:00Z")).toBe("Containing, not proven");
  });

  it("never outlives a poll and its grace, so a stalled read is not proof", () => {
    const snapshot = read();
    expect(chip(snapshot, GENERATED)).toBe("Protecting");
    const edge = Date.parse(GENERATED) + POSTURE_REFRESH_MS + HOLD_GRACE_MS;
    expect(chip(snapshot, new Date(edge).toISOString())).toBe("Protecting");
    expect(chip(snapshot, new Date(edge + 1_000).toISOString())).toBe("Containing, not proven");
    // Once lapsed it stays lapsed on that read.
    expect(chip(snapshot, new Date(edge - 1_000).toISOString())).toBe("Containing, not proven");
  });

  it("reads a withdrawal the way the page's own check would", () => {
    const now = Date.parse(GENERATED);
    expect(bootstrapStillBacks(layer(), bootstrap, now)).toBe(true);
    expect(bootstrapStillBacks(layer(), withdrawn(), now)).toBe(false);
    expect(bootstrapStillBacks(layer(), { ...bootstrap, capabilities: [] }, now)).toBe(false);
    expect(bootstrapStillBacks(layer(), { ...bootstrap, assurance_matrix: null }, now)).toBe(false);
    expect(bootstrapStillBacks(layer(), bootstrap, Date.parse("2026-07-18T13:00:01Z"))).toBe(false);
    for (const change of [{ rollout_state: "observing" }, { effective_mode: "observe" }, { bypass_classes: ["x"] }, { known_uncovered_paths: ["y"] }, { support: "partial" }]) {
      expect(bootstrapStillBacks(layer(), { ...bootstrap, capabilities: [{ ...capability(), ...change } as CapabilityStatus] }, now), JSON.stringify(change)).toBe(false);
    }
  });
});

/**
 * The host's own count ("The host counts 3 of 5 controls actively
 * containing") is a second count from a second source. Under the headline
 * in the plain view it read as a second verdict; it stays for whoever checks
 * one against the other.
 */
describe("the host's own control count", () => {
  it("is behind the technical switch", () => {
    const counted = { ...read(), enforcing_count: 1, control_count: 1 };
    setTechnicalDetail(false);
    expect(renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={counted} current evaluatedAt={GENERATED} />)).not.toContain("actively containing");
    setTechnicalDetail(true);
    expect(renderToStaticMarkup(<Posture bootstrap={bootstrap} posture={counted} current evaluatedAt={GENERATED} />)).toContain("The host counts 1 of 1 control actively containing.");
  });
});
