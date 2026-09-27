import { describe, expect, it } from "vitest";
import { outcomeTone } from "./LaneCards";
import { statusPresentation, type StatusTone } from "./StatusBadge";

describe("statusPresentation", () => {
  it("keeps long canonical outcomes semantic without relying on colour", () => {
    expect(statusPresentation("blocked_before_execution")).toEqual({
      label: "Blocked before execution",
      symbol: "■",
      tone: "stopped",
    });
  });

  /**
   * One outcome, one colour, on every screen: the badge wears the family the
   * lane bars and the case rows draw the same key in (`outcomeTone`). The
   * Overview drew a kernel stop rose while Cases drew it cyan, one click
   * apart.
   *
   * FAILS ON REVERT: contained is emerald, a refusal before it ran red and
   * "would block" amber again, and none matches its bar.
   */
  it("draws every case outcome in the family its lane bar draws it in", () => {
    const family = (key: string): StatusTone => {
      const tone = outcomeTone(key).tone;
      if (tone === "accent" || tone === "accentLight") return "stopped";
      if (tone === "bad") return "critical";
      return "neutral";
    };
    for (const key of ["contained", "blocked_before_execution", "failed", "would_block", "observed_only", "reverted", "not_observed", "unknown"]) {
      expect(statusPresentation(key).tone, key).toBe(family(key));
    }
  });

  it("labels weak and conflicting identity without implying trust", () => {
    expect(statusPresentation("declared").label).toBe("Declared only");
    expect(statusPresentation("conflicting")).toMatchObject({ label: "Conflicting identity", symbol: "×" });
    expect(statusPresentation("unattributed")).toMatchObject({ label: "Unattributed", symbol: "?" });
  });

  it("keeps arbitrary future labels readable and neutral", () => {
    expect(statusPresentation("custom_extremely_long_status_label")).toEqual({
      label: "Custom extremely long status label",
      symbol: "•",
      tone: "neutral",
    });
  });
});
