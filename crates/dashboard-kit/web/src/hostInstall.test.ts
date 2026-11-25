import { describe, expect, it } from "vitest";
import { hostInstallOf } from "./hostInstall";

/**
 * The host installer installs the host install with or without a licence,
 * and the page called any of them "InnerWarden Pro". The meta now carries
 * the licence the CLI reads (`host_install`), and the page reads it here.
 */
describe("the host install the meta reports", () => {
  it("is none where none is installed, whatever else the meta says", () => {
    expect(hostInstallOf(undefined)).toBeUndefined();
    expect(hostInstallOf({})).toBeUndefined();
    expect(hostInstallOf({ active_defence_installed: false, host_install: "pro" })).toBeUndefined();
  });

  it("is named by the licence the server reported", () => {
    // FAILS ON REVERT: "installed" alone was read as InnerWarden Pro.
    expect(hostInstallOf({ active_defence_installed: true, host_install: "pro" })).toBe("pro");
    expect(hostInstallOf({ active_defence_installed: true, host_install: "free_tier" })).toBe("free_tier");
    expect(hostInstallOf({ active_defence_installed: true, host_install: "unknown" })).toBe("unknown");
  });

  it("has no tier where the server did not say one it knows", () => {
    // An older server sends only `active_defence_installed`.
    expect(hostInstallOf({ active_defence_installed: true })).toBe("unknown");
    expect(hostInstallOf({ active_defence_installed: true, host_install: "enterprise" })).toBe("unknown");
    expect(hostInstallOf({ active_defence_installed: true, host_install: "PRO" })).toBe("unknown");
  });
});
