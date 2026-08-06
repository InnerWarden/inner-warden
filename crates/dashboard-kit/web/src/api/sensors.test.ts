import { describe, expect, it } from "vitest";
import {
  SENSOR_ABSENT_STATUSES,
  fetchSensorActivity,
  parseSensorActivity,
  sensorOutcomeForStatus,
} from "./sensors";

const PAYLOAD = {
  date: "2026-08-06",
  total_events: 1_204,
  total_incidents: 3,
  sources: [{ name: "ebpf", count: 1_200 }, { name: "tls_fingerprint", count: 0 }],
  top_kinds: [{ name: "exec", count: 900 }],
  detectors: [{ name: "reverse_shell", count: 2 }],
  event_timeline: { "09:07": { ebpf: 1_200 } },
  detector_timeline: { "09:07": { reverse_shell: 2 } },
  collector_health: {
    generated_at: "2026-08-06T03:00:00+00:00",
    host: "prod-1",
    statuses: [{ name: "ebpf", category: "telemetry", health: { state: "active" }, source: null }],
  },
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

describe("sensorOutcomeForStatus", () => {
  it.each(SENSOR_ABSENT_STATUSES)("reads %i as an absence, not a failure", (status) => {
    expect(sensorOutcomeForStatus(status)).toBe("absent");
  });

  it.each([400, 401, 403, 500, 502, 503])("reads %i as a failure", (status) => {
    expect(sensorOutcomeForStatus(status)).toBe("unavailable");
  });
});

describe("parseSensorActivity", () => {
  it("reads the payload the paid agent serves", () => {
    const parsed = parseSensorActivity(PAYLOAD);
    expect(parsed?.date).toBe("2026-08-06");
    expect(parsed?.total_events).toBe(1_204);
    expect(parsed?.sources).toEqual(PAYLOAD.sources);
    expect(parsed?.event_timeline).toEqual(PAYLOAD.event_timeline);
    expect(parsed?.collector_health?.statuses[0].health?.state).toBe("active");
  });

  /**
   * `sources` and `event_timeline` ARE the panel. Defaulting them to empty would
   * report "no collectors on this host" about a response that never said that.
   */
  it.each([
    ["not an object", 42],
    ["no sources", { event_timeline: {} }],
    ["no timeline", { sources: [] }],
    ["sources that is not an array", { sources: {}, event_timeline: {} }],
  ])("refuses a body with %s", (_label, body) => {
    expect(parseSensorActivity(body)).toBeUndefined();
  });

  it("keeps a totals field it was not sent as null rather than zero", () => {
    const parsed = parseSensorActivity({ sources: [], event_timeline: {} });
    expect(parsed?.total_events).toBeNull();
    expect(parsed?.total_incidents).toBeNull();
  });

  it("keeps a roster row whose count did not arrive, without inventing silence", () => {
    const parsed = parseSensorActivity({ sources: [{ name: "ebpf" }, { count: 4 }], event_timeline: {} });
    expect(parsed?.sources).toEqual([{ name: "ebpf", count: 0 }]);
  });

  it("treats a health block without statuses as no health file at all", () => {
    expect(parseSensorActivity({ sources: [], event_timeline: {}, collector_health: null })?.collector_health).toBeNull();
    expect(parseSensorActivity({ sources: [], event_timeline: {}, collector_health: {} })?.collector_health).toBeNull();
  });

  it("does not normalise an unrecognised health state into something benign", () => {
    const parsed = parseSensorActivity({
      sources: [],
      event_timeline: {},
      collector_health: { statuses: [{ name: "ebpf", health: { state: "some_future_state" } }] },
    });
    expect(parsed?.collector_health?.statuses[0].health?.state).toBe("some_future_state");
  });
});

/**
 * THE DEGRADE PATH.
 *
 * The free CLI answers a JSON 404 for every unknown `/api/*` route, so on that
 * product this endpoint is absent by design. The call must resolve, never throw,
 * and never report an absence as a fault.
 */
describe("fetchSensorActivity", () => {
  it("reports the free product's 404 as an absence", async () => {
    const outcome = await fetchSensorActivity(async () => json({ error: "not found" }, 404));
    expect(outcome).toEqual({ state: "absent" });
  });

  it("does not throw when the endpoint is missing", async () => {
    await expect(fetchSensorActivity(async () => json({ error: "not found" }, 404))).resolves.toBeDefined();
  });

  it("reports a server fault as unavailable, which the panel retries", async () => {
    expect(await fetchSensorActivity(async () => json({}, 503))).toEqual({ state: "unavailable" });
  });

  it("reports a network failure as unavailable rather than throwing", async () => {
    const outcome = await fetchSensorActivity(async () => { throw new TypeError("Failed to fetch"); });
    expect(outcome).toEqual({ state: "unavailable" });
  });

  it("treats a 200 that is not this contract as an absence, never as data", async () => {
    expect(await fetchSensorActivity(async () => json({ hello: "world" }))).toEqual({ state: "absent" });
    expect(await fetchSensorActivity(async () => new Response("<!doctype html>", { status: 200 }))).toEqual({ state: "absent" });
  });

  it("returns the parsed payload on success", async () => {
    const outcome = await fetchSensorActivity(async () => json(PAYLOAD));
    expect(outcome.state).toBe("ready");
    if (outcome.state === "ready") expect(outcome.data.sources).toEqual(PAYLOAD.sources);
  });

  it("asks the same-origin relative path both products serve their API from", async () => {
    const seen: string[] = [];
    await fetchSensorActivity(async (input) => {
      seen.push(String(input));
      return json(PAYLOAD);
    });
    expect(seen).toEqual(["api/sensors"]);
  });
});
