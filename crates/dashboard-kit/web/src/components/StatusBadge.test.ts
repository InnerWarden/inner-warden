import { describe, expect, it } from "vitest";
import { statusPresentation } from "./StatusBadge";

describe("statusPresentation", () => {
  it("keeps long canonical outcomes semantic without relying on colour", () => {
    expect(statusPresentation("blocked_before_execution")).toEqual({
      label: "Blocked before execution",
      symbol: "×",
      tone: "critical",
    });
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
