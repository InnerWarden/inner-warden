import { describe, expect, it } from "vitest";
import {
  boardSummary,
  captionCounts,
  collectorCategory,
  collectorGroups,
  collectorRows,
  sensorPanelState,
  sharedStateNote,
} from "./board";
import type { SensorActivity } from "../api/sensors";

function activity(over: Partial<SensorActivity> = {}): SensorActivity {
  return {
    date: "2026-08-06",
    total_events: 0,
    total_incidents: 0,
    sources: [],
    top_kinds: [],
    detectors: [],
    event_timeline: {},
    collector_health: null,
    ...over,
  };
}

const rowFor = (payload: SensorActivity, name: string) => {
  const row = collectorRows(payload).find((candidate) => candidate.name === name);
  if (row === undefined) throw new Error(`no row for ${name}`);
  return row;
};

describe("collectorCategory", () => {
  it("prefers the category the sensor declared over the bundled table", () => {
    expect(collectorCategory("ebpf")).toBe("telemetry");
    expect(collectorCategory("ebpf", "alarm")).toBe("alarm");
  });

  it("ignores a category the contract does not define", () => {
    expect(collectorCategory("docker", "something_else")).toBe("alarm");
  });

  /**
   * A stranger is read as telemetry, matching the sensor's own `category_for`.
   * Reading it as an alarm would file its silence under "healthy" and hide a
   * collector nobody knew had stopped.
   */
  it("reads an unknown collector as telemetry, the loud default", () => {
    expect(collectorCategory("brand_new_collector")).toBe("telemetry");
  });
});

/**
 * THE RULE THIS FILE EXISTS FOR.
 *
 * A production host ran with zero eBPF programs attached while the surface above
 * it reported the collector as fine. Declared is not attached, and no branch
 * below may turn one into the other.
 */
describe("a declared collector is not an active one", () => {
  it("does not read as active when the sensor reports the source is missing", () => {
    const payload = activity({
      sources: [{ name: "ebpf", count: 0 }],
      collector_health: {
        statuses: [{ name: "ebpf", category: "telemetry", health: { state: "source_unavailable", path: "/sys/fs/bpf" } }],
      },
    });
    const row = rowFor(payload, "ebpf");
    expect(row.active).toBe(false);
    expect(row.liveness).toBe("impaired");
    expect(row.label).toBe("Source missing");
    expect(row.tone).toBe("warning");
    // A fault is a fact about THIS row, so it stays inline on the row rather
    // than moving to the shared legend, which has no shared sentence for it.
    expect(row.note).toContain("/sys/fs/bpf");
    expect(sharedStateNote("telemetry", "impaired")).toBeUndefined();
  });

  it("does not read as active when nothing attested it at all", () => {
    const payload = activity({ sources: [{ name: "ebpf", count: 0 }] });
    const row = rowFor(payload, "ebpf");
    expect(row.active).toBe(false);
    expect(row.liveness).toBe("unattested");
    expect(row.label).toBe("Not attested");
    expect(row.state).toBe("not_reported");
    expect(row.tone).toBe("warning");
    expect(row.noteKey).toBe("unattested");
    expect(sharedStateNote("telemetry", "unattested")).toContain("Declared is not attached");
  });

  it("keeps the fault verdict even when events also arrived, and shows both", () => {
    const payload = activity({
      sources: [{ name: "auth_log", count: 90 }],
      collector_health: {
        statuses: [{ name: "auth_log", health: { state: "source_empty", path: "/var/log/auth.log", last_write_iso: "2026-07-30T02:00:00Z" } }],
      },
    });
    const row = rowFor(payload, "auth_log");
    expect(row.active).toBe(false);
    expect(row.label).toBe("Source stale");
    expect(row.note).toContain("2026-07-30T02:00:00Z");
    expect(row.note).toContain("90 events were still recorded today");
  });

  it.each([
    ["permission_denied", "No permission"],
    ["unsupported", "Unsupported"],
  ])("does not read as active for %s", (state, label) => {
    const payload = activity({
      sources: [{ name: "dns_capture", count: 0 }],
      collector_health: { statuses: [{ name: "dns_capture", health: { state, reason: "no CAP_NET_RAW" } }] },
    });
    const row = rowFor(payload, "dns_capture");
    expect(row.active).toBe(false);
    expect(row.label).toBe(label);
  });

  /**
   * Serde emits `disabled_by_config` for the Rust `DisabledByConfig` variant.
   * The deleted frontend tested for `"disabled"` and therefore never matched
   * one; both spellings are accepted so that mismatch cannot come back.
   */
  it.each(["disabled_by_config", "disabled"])("treats %s as switched off, not as running", (state) => {
    const payload = activity({
      sources: [{ name: "docker", count: 0 }],
      collector_health: { statuses: [{ name: "docker", category: "alarm", health: { state } }] },
    });
    const row = rowFor(payload, "docker");
    expect(row.liveness).toBe("disabled");
    expect(row.active).toBe(false);
    expect(row.label).toBe("Disabled");
  });
});

describe("zero events is a state, not an error", () => {
  it("calls a silent telemetry stream out, even though the sensor attests it", () => {
    const payload = activity({
      sources: [{ name: "journald", count: 0 }],
      collector_health: { statuses: [{ name: "journald", category: "telemetry", health: { state: "active" } }] },
    });
    const row = rowFor(payload, "journald");
    expect(row.active).toBe(true);
    expect(row.liveness).toBe("quiet");
    expect(row.tone).toBe("attention");
    expect(row.label).toBe("Attached, silent");
    expect(sharedStateNote("telemetry", "quiet")).toContain("worth chasing");
  });

  it("reads a silent alarm detector as healthy", () => {
    const payload = activity({
      sources: [{ name: "tls_fingerprint", count: 0 }],
      collector_health: { statuses: [{ name: "tls_fingerprint", category: "alarm", health: { state: "active" } }] },
    });
    const row = rowFor(payload, "tls_fingerprint");
    expect(row.active).toBe(true);
    expect(row.liveness).toBe("quiet");
    expect(row.tone).toBe("positive");
    expect(row.label).toBe("Quiet");
    expect(sharedStateNote("alarm", "quiet")).toContain("healthy state");
  });

  it("reads a firing alarm detector as a finding, not as good news", () => {
    const payload = activity({
      sources: [{ name: "integrity", count: 4 }],
      collector_health: { statuses: [{ name: "integrity", category: "alarm", health: { state: "active" } }] },
    });
    const row = rowFor(payload, "integrity");
    expect(row.liveness).toBe("reporting");
    expect(row.tone).toBe("attention");
    expect(row.count).toBe(4);
    expect(sharedStateNote("alarm", "reporting")).toContain("findings");
  });

  it("never hides a collector reporting zero", () => {
    const payload = activity({
      sources: [{ name: "ebpf", count: 0 }, { name: "auditd", count: 0 }, { name: "journald", count: 12 }],
    });
    expect(collectorRows(payload).map((row) => row.name)).toEqual(["auditd", "ebpf", "journald"]);
  });
});

describe("collectorRows", () => {
  it("unions both rosters, so neither list can drop a collector", () => {
    const payload = activity({
      sources: [{ name: "journald", count: 3 }],
      collector_health: { statuses: [{ name: "usb_monitor", category: "alarm", health: { state: "active" } }] },
    });
    expect(collectorRows(payload).map((row) => row.name)).toEqual(["journald", "usb_monitor"]);
  });

  it("counts events without a health verdict as evidence it produced something", () => {
    const row = rowFor(activity({ sources: [{ name: "journald", count: 400 }] }), "journald");
    expect(row.liveness).toBe("reporting");
    expect(row.active).toBe(true);
    // A distinct pill from the attested "Reporting": two rows with the same
    // label must mean the same thing.
    expect(row.label).toBe("Reporting, no verdict");
    expect(sharedStateNote("telemetry", "reporting_no_verdict")).toContain("published no health verdict");
  });
});

describe("collectorGroups", () => {
  const payload = activity({
    sources: [
      { name: "journald", count: 900 },
      { name: "ebpf", count: 0 },
      { name: "tls_fingerprint", count: 0 },
      { name: "suid_inventory", count: 2 },
    ],
    collector_health: {
      statuses: [
        { name: "journald", category: "telemetry", health: { state: "active" } },
        { name: "tls_fingerprint", category: "alarm", health: { state: "active" } },
        { name: "suid_inventory", category: "snapshot", health: { state: "active" } },
      ],
    },
  });

  it("groups by category and drops no row", () => {
    const groups = collectorGroups(collectorRows(payload));
    expect(groups.map((group) => group.category)).toEqual(["telemetry", "alarm", "snapshot"]);
    expect(groups.flatMap((group) => group.rows)).toHaveLength(4);
  });

  it("puts what needs attention above what does not", () => {
    const telemetry = collectorGroups(collectorRows(payload))[0];
    expect(telemetry.rows.map((row) => row.name)).toEqual(["ebpf", "journald"]);
    expect(telemetry.caption).toContain("not confirmed running");
  });

  it("omits a category this host has no collectors for", () => {
    const groups = collectorGroups(collectorRows(activity({ sources: [{ name: "journald", count: 1 }] })));
    expect(groups.map((group) => group.category)).toEqual(["telemetry"]);
  });
});

/**
 * THE REPETITION RULE.
 *
 * The first shipped board printed each state's explanation on every row in that
 * state: "Declared, with no events today..." five times in a row, "The sensor
 * reports the source is live..." four times. The explanation now lives once per
 * group as a legend note, and a row may only carry prose that is about that row
 * alone.
 */
describe("each state's explanation is said once per group", () => {
  const payload = activity({
    sources: [
      { name: "auditd", count: 0 },
      { name: "dns_capture", count: 0 },
      { name: "ebpf", count: 0 },
      { name: "http_capture", count: 0 },
      { name: "proc_maps", count: 0 },
      { name: "journald", count: 0 },
      { name: "auth_log", count: 0 },
      { name: "tcp_stream", count: 900 },
    ],
    collector_health: {
      statuses: [
        { name: "journald", category: "telemetry", health: { state: "active" } },
        { name: "auth_log", category: "telemetry", health: { state: "active" } },
        { name: "tcp_stream", category: "telemetry", health: { state: "active" } },
      ],
    },
  });

  it("renders one legend note per state present, not one per row", () => {
    const [telemetry] = collectorGroups(collectorRows(payload));
    expect(telemetry.rows).toHaveLength(8);
    // Five unattested rows and two quiet rows collapse to ONE note each.
    expect(telemetry.notes.map((note) => note.key)).toEqual(["unattested", "quiet", "reporting"]);
  });

  it("keeps the legend in the rows' worst-first order, under matching labels", () => {
    const [telemetry] = collectorGroups(collectorRows(payload));
    expect(telemetry.notes.map((note) => note.label)).toEqual(["Not attested", "Attached, silent", "Reporting"]);
    expect(telemetry.notes.map((note) => note.tone)).toEqual(["warning", "attention", "positive"]);
    expect(telemetry.notes[0].text).toContain("Declared is not attached");
  });

  it("puts no shared boilerplate on the rows themselves", () => {
    for (const row of collectorRows(payload)) expect(row.note).toBeUndefined();
  });

  it("still gives an impaired row its own inline fact, because a fault is not shared", () => {
    const rows = collectorRows(activity({
      sources: [{ name: "ebpf", count: 0 }, { name: "auditd", count: 0 }],
      collector_health: {
        statuses: [
          { name: "ebpf", category: "telemetry", health: { state: "source_unavailable", path: "/sys/fs/bpf" } },
          { name: "auditd", category: "telemetry", health: { state: "permission_denied" } },
        ],
      },
    }));
    const [telemetry] = collectorGroups(rows);
    expect(telemetry.notes.map((note) => note.key)).not.toContain("impaired");
    const notes = telemetry.rows.map((row) => row.note);
    expect(notes.every((note) => note !== undefined)).toBe(true);
    // Two impaired rows, two different facts. Nothing repeats.
    expect(new Set(notes).size).toBe(2);
  });

  it("shares the disabled explanation instead of restating it per row", () => {
    expect(sharedStateNote("alarm", "disabled")).toContain("Nothing is watching");
    expect(sharedStateNote("telemetry", "disabled")).toContain("not being collected");
    const rows = collectorRows(activity({
      sources: [{ name: "docker", count: 0 }],
      collector_health: { statuses: [{ name: "docker", category: "alarm", health: { state: "disabled_by_config" } }] },
    }));
    expect(rows[0].noteKey).toBe("disabled");
    expect(rows[0].note).toBeUndefined();
  });
});

/**
 * THE CAPTION IS A PARTITION.
 *
 * An operator counted the rows: "10 of 15 reporting, 4 not confirmed running"
 * over a group where 5 rows were not reporting. The two halves of the caption
 * used different predicates (`liveness === "reporting"` and `!active`) and the
 * quiet row was in neither, so it vanished from the sentence. A disabled row
 * had the opposite problem: it was counted as doubt when it is a decision.
 */
describe("the caption accounts for every row in the group", () => {
  const payload = activity({
    sources: [
      { name: "journald", count: 5 },
      { name: "auth_log", count: 0 },
      { name: "ebpf", count: 0 },
      { name: "auditd", count: 0 },
      { name: "dns_capture", count: 0 },
    ],
    collector_health: {
      statuses: [
        { name: "journald", category: "telemetry", health: { state: "active" } },
        { name: "auth_log", category: "telemetry", health: { state: "active" } },
        { name: "auditd", category: "telemetry", health: { state: "disabled_by_config" } },
        { name: "dns_capture", category: "telemetry", health: { state: "permission_denied" } },
      ],
    },
  });

  // FAILS ON REVERT: the old caption read "1 of 5 reporting · 3 not confirmed
  // running", which both dropped the quiet row and counted the disabled one as
  // an unknown.
  it("names the silent row instead of leaving it out of the sentence", () => {
    const [telemetry] = collectorGroups(collectorRows(payload));
    expect(telemetry.rows).toHaveLength(5);
    expect(telemetry.caption).toContain("1 of 5 reporting");
    expect(telemetry.caption).toContain("1 attached but silent");
    expect(telemetry.caption).toContain("2 not confirmed running");
  });

  it("calls a disabled collector switched off, not unconfirmed", () => {
    const [telemetry] = collectorGroups(collectorRows(payload));
    expect(telemetry.caption).toContain("1 switched off");
    expect(telemetry.caption).not.toContain("3 not confirmed running");
  });

  it("puts every liveness in exactly one bucket, so nothing can go uncounted", () => {
    const [telemetry] = collectorGroups(collectorRows(payload));
    const counts = captionCounts(telemetry.rows);
    expect(counts).toEqual({ reporting: 1, silent: 1, notRunning: 2, disabled: 1 });
    expect(counts.reporting + counts.silent + counts.notRunning + counts.disabled)
      .toBe(telemetry.rows.length);
  });

  it("uses each category's own word for silence, matching the pill on the row", () => {
    const alarms = collectorGroups(collectorRows(activity({
      sources: [{ name: "tls_fingerprint", count: 0 }, { name: "usb_monitor", count: 0 }],
      collector_health: {
        statuses: [
          { name: "tls_fingerprint", category: "alarm", health: { state: "active" } },
          { name: "usb_monitor", category: "alarm", health: { state: "active" } },
        ],
      },
    })))[0];
    expect(alarms.rows.every((row) => row.label === "Quiet")).toBe(true);
    expect(alarms.caption).toBe("0 of 2 with findings · 2 quiet");
  });
});

describe("boardSummary", () => {
  it("counts what is not confirmed running, because that is the actionable number", () => {
    const rows = collectorRows(activity({
      sources: [{ name: "ebpf", count: 0 }, { name: "auth_log", count: 0 }, { name: "journald", count: 5 }],
      collector_health: {
        statuses: [
          { name: "auth_log", health: { state: "source_unavailable", path: "/var/log/auth.log" } },
          { name: "journald", health: { state: "active" } },
        ],
      },
    }));
    expect(boardSummary(rows)).toBe("3 collectors: 1 reporting a fault, 1 declared but not attested.");
  });

  it("says so plainly when everything is confirmed", () => {
    const rows = collectorRows(activity({
      sources: [{ name: "journald", count: 5 }],
      collector_health: { statuses: [{ name: "journald", health: { state: "active" } }] },
    }));
    expect(boardSummary(rows)).toBe("1 collectors, all confirmed running.");
  });

  it("does not invent collectors for a host that listed none", () => {
    expect(boardSummary([])).toBe("No collectors were reported by this host.");
  });

  /**
   * An operator read "25 collectors: 1 attached but silent" above two rows both
   * labelled "Attached, silent". The headline counted telemetry only, while the
   * pill is worn by every quiet row outside the alarm group.
   *
   * FAILS ON REVERT: the telemetry-only filter says 1 where two rows say it.
   */
  it("counts every row wearing the silent pill, not the telemetry ones only", () => {
    const rows = collectorRows(activity({
      sources: [
        { name: "file_extract", count: 0 },
        { name: "suid_inventory", count: 0 },
        { name: "tls_fingerprint", count: 0 },
      ],
      collector_health: {
        statuses: [
          { name: "file_extract", category: "telemetry", health: { state: "active" } },
          { name: "suid_inventory", category: "snapshot", health: { state: "active" } },
          { name: "tls_fingerprint", category: "alarm", health: { state: "active" } },
        ],
      },
    }));
    expect(rows.filter((row) => row.label === "Attached, silent")).toHaveLength(2);
    expect(boardSummary(rows)).toBe("3 collectors: 2 attached but silent.");
  });

  /**
   * FAILS ON REVERT: with disabled unsaid, a board whose docker detector is
   * switched off summarised itself as "2 collectors, all confirmed running",
   * which is the exact sentence this function exists to never print.
   */
  it("says what was switched off instead of absorbing it into the total", () => {
    const rows = collectorRows(activity({
      sources: [{ name: "journald", count: 5 }, { name: "docker", count: 0 }],
      collector_health: {
        statuses: [
          { name: "journald", category: "telemetry", health: { state: "active" } },
          { name: "docker", category: "alarm", health: { state: "disabled_by_config" } },
        ],
      },
    }));
    expect(boardSummary(rows)).toBe("2 collectors: 1 switched off.");
    expect(boardSummary(rows)).not.toContain("all confirmed running");
  });
});

/**
 * THE DEGRADE PATH.
 *
 * `/api/sensors` does not exist on the free product. Every state that is not
 * "we have a payload" renders NOTHING: a skeleton, an empty panel or an error
 * box would each tell that operator there is host sensor data here.
 */
describe("sensorPanelState", () => {
  it("renders nothing while the first request is in flight", () => {
    expect(sensorPanelState({ status: "loading" })).toEqual({ render: "hidden" });
  });

  it("renders nothing when the endpoint is not served here", () => {
    expect(sensorPanelState({ status: "absent" })).toEqual({ render: "hidden" });
  });

  it("renders nothing when the endpoint failed and nothing had arrived yet", () => {
    expect(sensorPanelState({ status: "failed" })).toEqual({ render: "hidden" });
  });

  it("renders the panel once a payload has arrived", () => {
    const data = activity();
    expect(sensorPanelState({ status: "ready", data })).toEqual({ render: "panel", data, stale: false });
  });

  it("keeps the last payload through a failure and marks it stale", () => {
    const data = activity();
    expect(sensorPanelState({ status: "failed", data })).toEqual({ render: "panel", data, stale: true });
  });
});

describe("verbatim fault notes are said once, not per row", () => {
  const activity = (statuses: object[], sources: object[]) =>
    ({ date: "2026-08-06", total_events: 0, total_incidents: 0, sources, top_kinds: [], detectors: [], event_timeline: {}, collector_health: { statuses } }) as never;

  // REGRESSION ANCHOR. Faults were exempt from the say-it-once rule as "row
  // facts", and adversarial review broke the exemption with a realistic case:
  // one missing CAP_NET_RAW impairs dns_capture AND tcp_stream at once, so the
  // identical permission_denied sentence rendered on both rows. A note two rows
  // share verbatim is boilerplate by definition.
  // FAILS ON REVERT: drop the hoistRepeatedNotes call and both rows carry it.
  it("hoists an identical permission_denied note to the group legend", () => {
    const rows = collectorRows(activity(
      [
        { name: "dns_capture", category: "telemetry", health: { state: "permission_denied" } },
        { name: "tcp_stream", category: "telemetry", health: { state: "permission_denied" } },
      ],
      [
        { name: "dns_capture", count: 0 },
        { name: "tcp_stream", count: 0 },
      ],
    ));
    const telemetry = collectorGroups(rows).find((group) => group.category === "telemetry")!;
    expect(telemetry.rows.filter((row) => row.note !== undefined)).toHaveLength(0);
    const hoisted = telemetry.notes.filter((note) => note.text.includes("lacks the OS capability"));
    expect(hoisted).toHaveLength(1);
    expect(hoisted[0].label).toContain("\u00d72");
  });

  it("keeps a genuinely unique fault inline on its row", () => {
    const rows = collectorRows(activity(
      [
        { name: "nginx_access", category: "telemetry", health: { state: "source_unavailable", path: "/var/log/nginx/access.log" } },
        { name: "auth_log", category: "telemetry", health: { state: "active" } },
      ],
      [
        { name: "nginx_access", count: 0 },
        { name: "auth_log", count: 3 },
      ],
    ));
    const telemetry = collectorGroups(rows).find((group) => group.category === "telemetry")!;
    const impaired = telemetry.rows.find((row) => row.name === "nginx_access")!;
    expect(impaired.note).toContain("/var/log/nginx/access.log");
  });
});
