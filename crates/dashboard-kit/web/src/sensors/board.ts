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
  detail: string;
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

function healthDetail(category: CollectorCategory, health: { state: string; path?: string; last_write_iso?: string; reason?: string }): string {
  switch (health.state) {
    case "source_unavailable":
      return `The sensor could not find ${health.path ?? "the configured source"} on this host. `
        + "Install the upstream service or remove the collector from the sensor config.";
    case "source_empty":
      return `${health.path ?? "The source"} exists but has not been written to since `
        + `${health.last_write_iso ?? "an unrecorded time"}. The upstream service has stopped writing.`;
    case "permission_denied":
      return "The sensor lacks the OS capability to read this source. Check the unit's AmbientCapabilities.";
    case "unsupported":
      return `Not supported on this host: ${health.reason ?? "no reason reported"}.`;
    default:
      return category === "alarm"
        ? "Disabled in the sensor config. Nothing is watching for this class of event."
        : "Disabled in the sensor config. This stream is not being collected.";
  }
}

function describe(name: string, count: number, category: CollectorCategory, status?: CollectorStatus): CollectorRow {
  const state = status?.health?.state?.toLowerCase();
  const row = (over: Pick<CollectorRow, "liveness" | "active" | "label" | "tone" | "detail">): CollectorRow => ({
    name,
    category,
    count,
    state: state ?? "not_reported",
    ...over,
  });

  if (state !== undefined && state in IMPAIRED_STATES) {
    const detail = healthDetail(category, status!.health!);
    return row({
      liveness: "impaired",
      active: false,
      label: IMPAIRED_STATES[state],
      tone: "warning",
      // A fault verdict beside a non-zero count is a contradiction, and hiding
      // either half would be the dishonest way to resolve it.
      detail: count > 0 ? `${detail} ${count.toLocaleString()} events were still recorded today.` : detail,
    });
  }

  if (state !== undefined && DISABLED_STATES.includes(state)) {
    return row({ liveness: "disabled", active: false, label: "Disabled", tone: "neutral", detail: healthDetail(category, status!.health!) });
  }

  if (state === "active") {
    if (count > 0) {
      return row({
        liveness: "reporting",
        active: true,
        label: "Reporting",
        tone: category === "alarm" ? "attention" : "positive",
        detail: category === "alarm"
          ? `${count.toLocaleString()} findings today. An alarm detector only speaks when something trips.`
          : `${count.toLocaleString()} events today, and the sensor reports the source is live.`,
      });
    }
    return row({
      liveness: "quiet",
      active: true,
      label: category === "alarm" ? "Quiet" : "Attached, silent",
      tone: category === "alarm" ? "positive" : "attention",
      detail: category === "alarm"
        ? "Attached and nothing has tripped today. For an alarm detector that is the healthy state."
        : category === "snapshot"
          ? "Attached; no snapshot cycle has been recorded today."
          : "The sensor reports the source is live, but no events have arrived today. An always-on stream at zero is worth chasing.",
    });
  }

  // No health verdict for this collector. Events are still direct evidence that
  // it produced something; their absence is evidence of nothing at all.
  if (count > 0) {
    return row({
      liveness: "reporting",
      active: true,
      label: "Reporting",
      tone: category === "alarm" ? "attention" : "positive",
      detail: `${count.toLocaleString()} events today. The sensor published no health verdict for it.`,
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
    detail: category === "telemetry"
      ? "Declared, with no events today and no health verdict from the sensor. Declared is not attached: a collector can be configured and have nothing bound in the kernel."
      : "Declared, with no events today and no health verdict from the sensor. Nothing here says it is attached.",
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

export type CollectorGroup = {
  category: CollectorCategory;
  title: string;
  /** One line saying how the zeros in this group should be read. */
  meaning: string;
  caption: string;
  rows: CollectorRow[];
};

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
    return {
      category,
      title: GROUP_TITLES[category],
      meaning: GROUP_MEANING[category],
      caption: caption(category, scoped),
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
