import { describe, expect, it } from "vitest";
import { formatMetricValue } from "./Metric";

describe("formatMetricValue", () => {
  it("preserves arbitrary precision decimal counters", () => {
    expect(formatMetricValue({
      availability: "available",
      value: "90071992547409931234567890",
      unit: "events",
    })).toBe("90,071,992,547,409,931,234,567,890 events");
  });

  it("renders unavailable values as state rather than zero", () => {
    expect(formatMetricValue({ availability: "unsupported", value: null, unit: null })).toBe("unsupported");
    expect(formatMetricValue({ availability: "not_configured", value: null, unit: null })).toBe("not configured");
  });
});
