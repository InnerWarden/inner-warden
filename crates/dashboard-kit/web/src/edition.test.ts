import { describe, expect, it } from "vitest";
import { resolveDashboardEdition } from "./edition";

describe("dashboard edition resolution", () => {
  it("does not release legacy screens while v1 and the compatibility probe are unresolved", () => {
    expect(resolveDashboardEdition(undefined, "loading", undefined, "loading")).toBeUndefined();
    expect(resolveDashboardEdition(undefined, "unavailable", undefined, "loading")).toBeUndefined();
  });

  it("keeps a neutral shell for an unversioned Enterprise signal", () => {
    expect(resolveDashboardEdition(undefined, "loading", "enterprise", "ready")).toBeUndefined();
    expect(resolveDashboardEdition(undefined, "unavailable", "enterprise", "ready")).toBeUndefined();
  });

  it("falls back only after an older Community binary is established", () => {
    expect(resolveDashboardEdition(undefined, "unavailable", "community", "ready")).toBe("community");
    expect(resolveDashboardEdition(undefined, "unavailable", undefined, "ready")).toBeUndefined();
    expect(resolveDashboardEdition(undefined, "unavailable", undefined, "error")).toBeUndefined();
  });

  it("treats a validated bootstrap as authoritative", () => {
    expect(resolveDashboardEdition({ edition: "community" }, "ready", "enterprise", "ready")).toBe("community");
    expect(resolveDashboardEdition({ edition: "enterprise" }, "ready", undefined, "error")).toBe("enterprise");
  });
});
