/**
 * The per-collector status board: what each collector IS, and what the host has
 * actually told us about it.
 *
 * The rule this file exists to enforce, stated once:
 *
 *   A collector that is DECLARED must never render as ACTIVE on the strength of
 *   being declared.
 *
 * That is not hypothetical. A production host ran with zero eBPF programs
 * attached while the surface above it reported the eBPF collector as fine,
 * because "it is in the config" and "it is running" had been allowed to become
 * the same sentence. Here they are three different sentences: the sensor's own
 * health verdict, the events actually observed today, and — when neither is
 * present — an explicit "not attested", which is never styled as good news.
 *
 * The second rule: zero is a legitimate answer, and which way it reads depends
 * on what the collector is for. Silence in an event-driven ALARM detector means
 * nothing has tripped, which is the healthy state. Silence in an always-on
 * TELEMETRY stream means the feed has stopped, which is worth chasing. Grouping
 * by category is what makes a zero readable.
 */
import type { CollectorCategory, CollectorStatus, SensorActivity } from "../api/sensors";

/**
 * Mirror of the sensor's `COLLECTOR_MANIFEST`
 * (`crates/sensor/src/collector_health.rs`).
 *
 * Only a FALLBACK. When the sensor writes its health file every row carries its
 * own `category` and that wins, so a collector added on the host side is
 * categorised correctly here without this table being touched. The table covers
 * the case where no health file exists at all.
 */
export const COLLECTOR_CATEGORY: Readonly<Record<string, CollectorCategory>> = {
  auth_log: "telemetry",
  auditd: "telemetry",
  cgroup: "telemetry",
  cloudtrail: "telemetry",
  dns_capture: "telemetry",
  ebpf: "telemetry",
  endpoint_security: "telemetry",
  etw: "telemetry",
  file_extract: "telemetry",
  http_capture: "telemetry",
  journald: "telemetry",
  kernel_integrity: "telemetry",
  macos_log: "telemetry",
  net_snapshot: "telemetry",
  nginx_access: "telemetry",
  nginx_error: "telemetry",
  proc_maps: "telemetry",
  proto_http: "telemetry",
  proto_smb: "telemetry",
  proto_ssh: "telemetry",
  syslog_firewall: "telemetry",
  tcp_stream: "telemetry",
  docker: "alarm",
  fanotify: "alarm",
  firmware_integrity: "alarm",
  integrity: "alarm",
  sysctl_drift: "alarm",
  tls_fingerprint: "alarm",
  usb_monitor: "alarm",
  suid_inventory: "snapshot",
  systemd_inventory: "snapshot",
};

const CATEGORIES: readonly CollectorCategory[] = ["telemetry", "alarm", "snapshot"];

/**
 * Which category a collector belongs to.
 *
 * An unrecognised collector falls back to `telemetry`, matching the sensor's own
 * `category_for`. That is the loud default on purpose: a stranger read as
 * telemetry shows up as a silent stream and gets investigated, where reading it
 * as an alarm would file its silence under "healthy" and hide it forever.
 */
export function collectorCategory(name: string, declared?: string): CollectorCategory {
  if (declared !== undefined && (CATEGORIES as readonly string[]).includes(declared)) {
    return declared as CollectorCategory;
  }
  return COLLECTOR_CATEGORY[name] ?? "telemetry";
}

/**
 * What we know about a collector's liveness. Deliberately five values, not a
 * boolean, because the interesting states are the ones a boolean has to lie
 * about.
 */
export type CollectorLiveness =
  /** Events were observed from it today. The only positive evidence there is. */
  | "reporting"
  /** The sensor attests the source is live; nothing has come through today. */
  | "quiet"
  /** The sensor reports a fault: missing source, stale source, no permission, unsupported. */
  | "impaired"
  /** Switched off in config. Operator choice, not a fault — and not running either. */
  | "disabled"
  /** Declared, and nothing has attested it. NOT a synonym for working. */
  | "unattested";

export type CollectorTone = "positive" | "attention" | "warning" | "neutral";

/**
 * Which shared explanation a row falls under.
 *
 * Rows in the same state used to each carry the full explanatory sentence, so a
 * board with five unattested collectors printed the same paragraph five times in
 * a row. The sentence now lives ONCE per group (see `sharedStateNote`), and the
 * row carries only this key. `impaired` is the exception: every fault is its own
 * fact (a path, a timestamp, a capability), so those rows keep an individual
 * `note` and have no shared sentence.
 */
export type CollectorNoteKey =
  | "reporting"
  | "reporting_no_verdict"
  | "quiet"
  | "disabled"
  | "unattested"
  | "impaired";

export type CollectorRow = {
  name: string;
  category: CollectorCategory;
  count: number;
  liveness: CollectorLiveness;
  /**
   * Whether this collector may be presented as running. True only for
   * `reporting` and `quiet` — never derived from the collector merely existing.
   */
  active: boolean;
  /** The raw health state, or `"not_reported"` when the host said nothing. */
  state: string;
  label: string;
  tone: CollectorTone;
  /** Key into the group's shared state notes. Identical rows share one sentence. */
  noteKey: CollectorNoteKey;
  /**
   * A fact about THIS row only, rendered inline beside it: the fault the sensor
   * reported, or a contradiction worth reading twice. Never shared boilerplate.
   */
  note?: string;
};

/** Health states that mean the collector is not doing its job. */
const IMPAIRED_STATES: Readonly<Record<string, string>> = {
  source_unavailable: "Source missing",
  source_empty: "Source stale",
  permission_denied: "No permission",
  unsupported: "Unsupported",
};

/**
 * Both spellings of "switched off in config".
 *
 * The Rust enum variant is `DisabledByConfig` and serde emits
 * `disabled_by_config`; the deleted frontend tested for `"disabled"` and so
 * never matched a single one — that branch was dead for the whole life of the
 * feature, and a disabled collector rendered under the generic warning pill.
 * Both are accepted here so neither side of that mismatch can resurrect it.
 */
const DISABLED_STATES: readonly string[] = ["disabled_by_config", "disabled"];

function faultNote(health: { state: string; path?: string; last_write_iso?: string; reason?: string }): string {
  switch (health.state) {
    case "source_unavailable":
      return `The sensor could not find ${health.path ?? "the configured source"} on this host. `
        + "Install the upstream service or remove the collector from the sensor config.";
    case "source_empty":
      return `${health.path ?? "The source"} exists but has not been written to since `
        + `${health.last_write_iso ?? "an unrecorded time"}. The upstream service has stopped writing.`;
    case "permission_denied":
      return "The sensor lacks the OS capability to read this source. Check the unit's AmbientCapabilities.";
    default:
      return `Not supported on this host: ${health.reason ?? "no reason reported"}.`;
  }
}

/**
 * The explanation for every row in `key`'s state, said ONCE per group.
 *
 * These sentences used to be copied onto each row, so identical boilerplate
 * repeated as many times as there were rows in the state. Nothing was removed in
 * the move: the same distinctions survive, per category, including the one this
 * panel exists to keep making, that silence is the healthy state for an alarm
 * and a stopped feed for a telemetry stream.
 *
 * `impaired` returns `undefined` on purpose: faults are row-specific facts and
 * live inline on the row, so a shared sentence would have nothing true to say.
 */
export function sharedStateNote(category: CollectorCategory, key: CollectorNoteKey): string | undefined {
  switch (key) {
    case "reporting":
      return category === "alarm"
        ? "The count is findings today. An alarm detector only speaks when something trips."
        : "Events arrived today, and the sensor reports the source is live.";
    case "reporting_no_verdict":
      return "Events arrived today, but the sensor published no health verdict for these collectors. "
        + "The events themselves are direct evidence they produced something.";
    case "quiet":
      return category === "alarm"
        ? "Attached and nothing has tripped today. For an alarm detector that is the healthy state."
        : category === "snapshot"
          ? "Attached; no snapshot cycle has been recorded today."
          : "The sensor reports the source is live, but no events have arrived today. An always-on stream at zero is worth chasing.";
    case "disabled":
      return category === "alarm"
        ? "Disabled in the sensor config. Nothing is watching for this class of event."
        : "Disabled in the sensor config. This stream is not being collected.";
    case "unattested":
      return category === "telemetry"
        ? "Declared, with no events today and no health verdict from the sensor. Declared is not attached: a collector can be configured and have nothing bound in the kernel."
        : "Declared, with no events today and no health verdict from the sensor. Nothing here says it is attached.";
    case "impaired":
      return undefined;
  }
}

function describe(name: string, count: number, category: CollectorCategory, status?: CollectorStatus): CollectorRow {
  const state = status?.health?.state?.toLowerCase();
  const row = (over: Pick<CollectorRow, "liveness" | "active" | "label" | "tone" | "noteKey"> & Partial<Pick<CollectorRow, "note">>): CollectorRow => ({
    name,
    category,
    count,
    state: state ?? "not_reported",
    ...over,
  });

  if (state !== undefined && state in IMPAIRED_STATES) {
    const fault = faultNote(status!.health!);
    return row({
      liveness: "impaired",
      active: false,
      label: IMPAIRED_STATES[state],
      tone: "warning",
      noteKey: "impaired",
      // A fault verdict beside a non-zero count is a contradiction, and hiding
      // either half would be the dishonest way to resolve it.
      note: count > 0 ? `${fault} ${count.toLocaleString()} events were still recorded today.` : fault,
    });
  }

  if (state !== undefined && DISABLED_STATES.includes(state)) {
    return row({ liveness: "disabled", active: false, label: "Disabled", tone: "neutral", noteKey: "disabled" });
  }

  if (state === "active") {
    if (count > 0) {
      return row({
        liveness: "reporting",
        active: true,
        label: "Reporting",
        tone: category === "alarm" ? "attention" : "positive",
        noteKey: "reporting",
      });
    }
    return row({
      liveness: "quiet",
      active: true,
      label: category === "alarm" ? "Quiet" : "Attached, silent",
      tone: category === "alarm" ? "positive" : "attention",
      noteKey: "quiet",
    });
  }

  // No health verdict for this collector. Events are still direct evidence that
  // it produced something; their absence is evidence of nothing at all.
  if (count > 0) {
    return row({
      liveness: "reporting",
      active: true,
      // A distinct label, not plain "Reporting": two rows with the same pill
      // must mean the same thing, and this one is running on the strength of
      // its own events rather than the sensor's attestation.
      label: "Reporting, no verdict",
      tone: category === "alarm" ? "attention" : "positive",
      noteKey: "reporting_no_verdict",
    });
  }

  return row({
    liveness: "unattested",
    active: false,
    label: "Not attested",
    // Loud for a stream that should never be at zero, neutral for the detectors
    // whose silence is ordinary — a warning on every quiet alarm would train the
    // operator to ignore the colour.
    tone: category === "telemetry" ? "warning" : "neutral",
    noteKey: "unattested",
  });
}

/**
 * Every collector this host knows about, from BOTH rosters.
 *
 * The event roster and the health roster can each hold a name the other does
 * not: a collector quiet since boot may never reach the counts, and one that
 * failed its probe may still be publishing. Taking either alone drops real rows.
 */
export function collectorRows(activity: SensorActivity): CollectorRow[] {
  const statuses = new Map<string, CollectorStatus>();
  for (const status of activity.collector_health?.statuses ?? []) statuses.set(status.name, status);

  const counts = new Map<string, number>();
  for (const source of activity.sources) counts.set(source.name, (counts.get(source.name) ?? 0) + source.count);

  const names = [...new Set([...counts.keys(), ...statuses.keys()])].sort((left, right) => left.localeCompare(right));
  return names.map((name) => {
    const status = statuses.get(name);
    return describe(name, counts.get(name) ?? 0, collectorCategory(name, status?.category), status);
  });
}

/** One state's explanation, rendered once for the whole group as a legend line. */
export type CollectorStateNote = {
  key: CollectorNoteKey;
  /** The same words as the pill on the rows it explains, so the two map by eye. */
  label: string;
  tone: CollectorTone;
  text: string;
};

export type CollectorGroup = {
  category: CollectorCategory;
  title: string;
  /** One line saying how the zeros in this group should be read. */
  meaning: string;
  caption: string;
  /**
   * One entry per state present in this group, worst first, matching the row
   * order. This is the ONLY place the shared explanations render: a state's
   * sentence appears exactly once no matter how many rows are in it.
   */
  notes: CollectorStateNote[];
  rows: CollectorRow[];
};

function groupNotes(category: CollectorCategory, rows: readonly CollectorRow[]): CollectorStateNote[] {
  const notes: CollectorStateNote[] = [];
  const seen = new Set<CollectorNoteKey>();
  for (const row of rows) {
    if (seen.has(row.noteKey)) continue;
    seen.add(row.noteKey);
    const text = sharedStateNote(category, row.noteKey);
    if (text !== undefined) notes.push({ key: row.noteKey, label: row.label, tone: row.tone, text });
  }
  return notes;
}

/**
 * Hoist an inline note that repeats VERBATIM across rows into the group legend,
 * and strip it from the rows that carried it.
 *
 * Faults were exempted from the say-it-once rule on the theory that "a fault is
 * its own fact". Adversarial review broke the theory with a realistic case: two
 * collectors both `permission_denied` (dns_capture and tcp_stream both need
 * CAP_NET_RAW, so one missing capability impairs several rows at once) render
 * the identical sentence on every row, exactly the repetition the redesign
 * exists to remove. A note is only a row-specific fact if no other row says the
 * same thing; when two rows say it verbatim, it is boilerplate by definition,
 * whatever we believed when we wrote it. Deduping on the RENDERED TEXT rather
 * than on the state also covers the pathless `source_unavailable` and the
 * reason-less `unsupported`, and any future state whose note forgets to carry a
 * fact.
 */
function hoistRepeatedNotes(rows: CollectorRow[], notes: CollectorStateNote[]): void {
  const byText = new Map<string, CollectorRow[]>();
  for (const row of rows) {
    if (row.note === undefined) continue;
    const carriers = byText.get(row.note);
    if (carriers === undefined) byText.set(row.note, [row]);
    else carriers.push(row);
  }
  for (const [text, carriers] of byText) {
    if (carriers.length < 2) continue;
    const first = carriers[0];
    notes.push({
      key: first.noteKey,
      label: `${first.label} \u00d7${carriers.length}`,
      tone: first.tone,
      text,
    });
    for (const row of carriers) row.note = undefined;
  }
}

const GROUP_TITLES: Record<CollectorCategory, string> = {
  telemetry: "Telemetry streams",
  alarm: "Alarm detectors",
  snapshot: "Snapshot collectors",
};

const GROUP_MEANING: Record<CollectorCategory, string> = {
  telemetry: "Always-on feeds. A stream at zero has stopped, and says so here rather than disappearing.",
  alarm: "Event-driven detectors. Silence is the healthy state; a count is a finding.",
  snapshot: "Periodic inventories. The count is completed cycles, not detections.",
};

function caption(category: CollectorCategory, rows: CollectorRow[]): string {
  if (rows.length === 0) return "None reported";
  const reporting = rows.filter((row) => row.liveness === "reporting").length;
  const notRunning = rows.filter((row) => !row.active).length;
  const head = category === "alarm"
    ? `${reporting} of ${rows.length} with findings`
    : `${reporting} of ${rows.length} reporting`;
  return notRunning === 0 ? head : `${head} · ${notRunning} not confirmed running`;
}

/**
 * Group the rows by category, hardest-to-read zeros first, and never hide an
 * empty group's absence behind a collapsed section.
 */
export function collectorGroups(rows: readonly CollectorRow[]): CollectorGroup[] {
  return CATEGORIES.map((category) => {
    const scoped = rows
      .filter((row) => row.category === category)
      .sort((left, right) => TONE_ORDER[left.tone] - TONE_ORDER[right.tone] || right.count - left.count || left.name.localeCompare(right.name));
    const notes = groupNotes(category, scoped);
    hoistRepeatedNotes(scoped, notes);
    return {
      category,
      title: GROUP_TITLES[category],
      meaning: GROUP_MEANING[category],
      caption: caption(category, scoped),
      notes,
      rows: scoped,
    };
  }).filter((group) => group.rows.length > 0);
}

/** Worst first. What needs attention should not be below the fold. */
const TONE_ORDER: Record<CollectorTone, number> = { warning: 0, attention: 1, neutral: 2, positive: 3 };

/**
 * The one-line verdict above the board.
 *
 * Counts what is NOT confirmed running rather than what is, because that is the
 * number an operator acts on, and because "18 collectors active" was exactly the
 * sentence that let a host with nothing attached look healthy.
 */
export function boardSummary(rows: readonly CollectorRow[]): string {
  if (rows.length === 0) return "No collectors were reported by this host.";
  const impaired = rows.filter((row) => row.liveness === "impaired").length;
  const unattested = rows.filter((row) => row.liveness === "unattested").length;
  const silentStreams = rows.filter((row) => row.category === "telemetry" && row.liveness === "quiet").length;
  const parts: string[] = [];
  if (impaired > 0) parts.push(`${impaired} reporting a fault`);
  if (unattested > 0) parts.push(`${unattested} declared but not attested`);
  if (silentStreams > 0) parts.push(`${silentStreams} attached but silent`);
  if (parts.length === 0) return `${rows.length} collectors, all confirmed running.`;
  return `${rows.length} collectors: ${parts.join(", ")}.`;
}

export type SensorFeedStatus = "loading" | "ready" | "absent" | "failed";
export type SensorFeed = { status: SensorFeedStatus; data?: SensorActivity };
export type SensorPanelState =
  | { render: "hidden" }
  | { render: "panel"; data: SensorActivity; stale: boolean };

/**
 * Whether to render the panel at all.
 *
 * The panel appears only once a real payload has arrived. Absent, loading and
 * failed-with-nothing-yet all render NOTHING: on the free product this endpoint
 * does not exist, and a skeleton, an empty panel or an error box would each tell
 * that operator there is host sensor data here waiting to load. There is not.
 *
 * A failure AFTER data keeps the data and marks it stale, which is the same
 * bargain the agents panel makes: older truth beats an empty box.
 */
export function sensorPanelState(feed: SensorFeed): SensorPanelState {
  if (feed.data === undefined) return { render: "hidden" };
  return { render: "panel", data: feed.data, stale: feed.status === "failed" };
}
