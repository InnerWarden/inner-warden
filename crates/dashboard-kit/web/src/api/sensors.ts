/**
 * `GET /api/sensors` — what the host sensor itself collected today, per collector.
 *
 * ONE bundle is served by two products. The paid Active Defence agent serves this
 * endpoint; the free CLI does not serve it at all and answers a JSON 404 for any
 * unknown `/api/*` path. So "this endpoint is not here" is a NORMAL answer on a
 * fully working host, and the reader below has to tell that apart from "the
 * endpoint is here and broke". Collapsing the two would either paint an error on
 * every free install or, worse, imply a sensor exists where none does.
 *
 * The payload is read defensively for the same reason `api.ts` reads the agent
 * guardrail defensively: rejecting a whole body over one unexpected field would
 * empty a panel that could have rendered almost all of its truth.
 */

export type CollectorCategory = "telemetry" | "alarm" | "snapshot";

export type NamedCount = { name: string; count: number };

/**
 * The sensor's own verdict on one collector, from the side-channel
 * `collector-health.json` it writes at boot.
 *
 * `state` is the serde tag of the Rust `CollectorHealth` enum. It is left as a
 * free string on purpose: an unknown state must reach the UI as an unknown
 * state, not be silently normalised into `active`.
 */
export type CollectorHealth = {
  state: string;
  path?: string;
  last_write_iso?: string;
  reason?: string;
};

export type CollectorStatus = {
  name: string;
  category?: string;
  health?: CollectorHealth;
  source?: string | null;
};

export type CollectorHealthReport = {
  generated_at?: string;
  host?: string;
  statuses: CollectorStatus[];
};

/** `{ "HH:MM": { collector: count } }`. Buckets are ONE MINUTE wide. */
export type EventTimeline = Record<string, Record<string, number>>;

export type SensorActivity = {
  date: string;
  /**
   * `null` when the producer sent no total. A missing total is printed as
   * "not reported"; it is never rendered as zero, because zero is a claim.
   */
  total_events: number | null;
  total_incidents: number | null;
  /**
   * The roster. A collector quiet today is deliberately still here with
   * `count: 0` — the producer unions the lifetime roster with today's counts
   * precisely so a UTC rollover cannot make 16 of 18 collectors vanish.
   */
  sources: NamedCount[];
  top_kinds: NamedCount[];
  detectors: NamedCount[];
  event_timeline: EventTimeline;
  /**
   * `null` when the sensor wrote no health file. That is "we were not told",
   * NOT "everything is fine", and nothing downstream may upgrade it.
   */
  collector_health: CollectorHealthReport | null;
};

export type SensorFeedOutcome =
  | { state: "ready"; data: SensorActivity }
  | { state: "absent" }
  | { state: "unavailable" };

/**
 * Statuses that mean "this product does not serve sensor activity", as opposed
 * to "it does and something went wrong". The free CLI answers 404; a producer
 * that gates the route answers 501. Both are honest absences and neither is
 * worth a word on screen.
 */
export const SENSOR_ABSENT_STATUSES: readonly number[] = [404, 410, 501];

export function sensorOutcomeForStatus(status: number): "absent" | "unavailable" {
  return SENSOR_ABSENT_STATUSES.includes(status) ? "absent" : "unavailable";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readCount(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function readNamedCounts(value: unknown): NamedCount[] {
  if (!Array.isArray(value)) return [];
  const rows: NamedCount[] = [];
  for (const entry of value) {
    if (!isRecord(entry) || typeof entry.name !== "string") continue;
    const count = readCount(entry.count);
    // A roster row whose count did not arrive is still a roster row. Dropping
    // it would hide a collector; inventing a count would fabricate silence.
    rows.push({ name: entry.name, count: count ?? 0 });
  }
  return rows;
}

function readTimeline(value: unknown): EventTimeline | undefined {
  if (!isRecord(value)) return undefined;
  const timeline: EventTimeline = {};
  for (const [bucket, sources] of Object.entries(value)) {
    if (!isRecord(sources)) continue;
    const inner: Record<string, number> = {};
    for (const [name, count] of Object.entries(sources)) {
      const parsed = readCount(count);
      if (parsed !== null) inner[name] = parsed;
    }
    timeline[bucket] = inner;
  }
  return timeline;
}

function readHealth(value: unknown): CollectorHealthReport | null {
  if (!isRecord(value) || !Array.isArray(value.statuses)) return null;
  const statuses: CollectorStatus[] = [];
  for (const entry of value.statuses) {
    if (!isRecord(entry) || typeof entry.name !== "string") continue;
    const health = isRecord(entry.health) && typeof entry.health.state === "string"
      ? {
        state: entry.health.state,
        ...(typeof entry.health.path === "string" ? { path: entry.health.path } : {}),
        ...(typeof entry.health.last_write_iso === "string" ? { last_write_iso: entry.health.last_write_iso } : {}),
        ...(typeof entry.health.reason === "string" ? { reason: entry.health.reason } : {}),
      }
      : undefined;
    statuses.push({
      name: entry.name,
      ...(typeof entry.category === "string" ? { category: entry.category } : {}),
      ...(health ? { health } : {}),
      ...(typeof entry.source === "string" ? { source: entry.source } : {}),
    });
  }
  return { statuses, ...(typeof value.generated_at === "string" ? { generated_at: value.generated_at } : {}), ...(typeof value.host === "string" ? { host: value.host } : {}) };
}

/**
 * Normalise a `/api/sensors` body, or refuse it.
 *
 * `sources` and `event_timeline` ARE the panel. A body without both carries
 * nothing to draw, and defaulting them to empty would report "no collectors on
 * this host" about a response that never claimed that. Everything else is
 * optional and degrades to "not reported".
 */
export function parseSensorActivity(value: unknown): SensorActivity | undefined {
  if (!isRecord(value)) return undefined;
  if (!Array.isArray(value.sources)) return undefined;
  const event_timeline = readTimeline(value.event_timeline);
  if (event_timeline === undefined) return undefined;
  return {
    date: typeof value.date === "string" ? value.date : "",
    total_events: readCount(value.total_events),
    total_incidents: readCount(value.total_incidents),
    sources: readNamedCounts(value.sources),
    top_kinds: readNamedCounts(value.top_kinds),
    detectors: readNamedCounts(value.detectors),
    event_timeline,
    collector_health: readHealth(value.collector_health),
  };
}

/**
 * Fetch sensor activity, reporting absence as its own outcome.
 *
 * A 200 that is not this contract is reported as ABSENT rather than as a
 * failure: the panel's whole promise is that it appears only when a real sensor
 * payload arrived, and a body we cannot read is not evidence that one did.
 */
export async function fetchSensorActivity(
  fetchImplementation: typeof globalThis.fetch = globalThis.fetch,
): Promise<SensorFeedOutcome> {
  const call = fetchImplementation.bind(globalThis);
  let response: Response;
  try {
    response = await call("api/sensors", { cache: "no-store", headers: { accept: "application/json" } });
  } catch {
    return { state: "unavailable" };
  }
  if (!response.ok) return { state: sensorOutcomeForStatus(response.status) };
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return { state: "absent" };
  }
  const data = parseSensorActivity(payload);
  return data === undefined ? { state: "absent" } : { state: "ready", data };
}
