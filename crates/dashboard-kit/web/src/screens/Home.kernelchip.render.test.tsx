import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DecisionSummary } from "../api";
import { KERNEL_STOPPED_OUTCOME, kernelStopped, kernelStoppedDetail, kernelStoppedLabel, RecentActivity } from "./Home";

/**
 * THE DEFECT THIS PINS
 *
 * `id && whoami && sudo -n true` was allowed by the rules, and the kernel
 * refused to start `/usr/bin/sudo` inside it. Recent activity said "Allowed"
 * and nothing else, so the product's strongest moment read as a pass. The host
 * now names the program the kernel stopped (`kernel_stopped`), and the entry
 * says so beside the verdict.
 */

const allowed: DecisionSummary = {
  id: "decision-allow",
  session: "wren-visitor-28eb7f9c",
  command: "id && sudo -n true && echo done",
  recommendation: "allow",
  outcome: "allowed",
  categories: [],
  decided_by: "rules",
};

function render(item: DecisionSummary): string {
  return renderToStaticMarkup(<RecentActivity items={[item]} edition="enterprise" onOpen={() => undefined} onOpenCase={() => undefined} />);
}

describe("a decision the kernel stopped part of", () => {
  /**
   * FAILS ON REVERT: drop the chip and the entry reads "Allowed" alone.
   */
  it("says the kernel stopped the program, by its name", () => {
    const html = render({ ...allowed, kernel_stopped: "/usr/bin/sudo" });
    expect(html).toContain("The kernel stopped sudo");
    expect(html).not.toContain("/usr/bin/sudo<");
  });

  it("says nothing about the kernel when the host sent no record of it", () => {
    expect(render(allowed)).not.toContain("kernel");
  });

  it("does not print a value it cannot vouch for", () => {
    for (const junk of ["", "   ", "x".repeat(513), "sudo\u0000", "bin\nsudo", 7, null]) {
      expect(kernelStopped({ kernel_stopped: junk as never })).toBeUndefined();
      expect(render({ ...allowed, kernel_stopped: junk as never })).not.toContain("The kernel stopped");
    }
  });

  it("names the program, not its path", () => {
    expect(kernelStoppedLabel("/usr/bin/sudo")).toBe("The kernel stopped sudo");
    expect(kernelStoppedLabel("sudo")).toBe("The kernel stopped sudo");
    expect(kernelStoppedLabel("/opt/tool/")).toBe("The kernel stopped tool");
  });
});

/**
 * One row read a green "Allowed", "Allowed to run" and "The kernel stopped
 * nc": the rule engine's verdict as the outcome, and the kernel's refusal as
 * a footnote. What finally happened is the kernel's refusal, so it is the
 * row's one outcome, and the verdict before it is said as what came first.
 *
 * FAILS ON REVERT: print the verdict pill and the outcome chip as before and
 * the row says "Allowed" twice beside a refusal.
 */
describe("the one outcome of a decision the kernel stopped", () => {
  it("is Stopped by the kernel, with no allowed pill or chip beside it", () => {
    const html = render({ ...allowed, command: "nc -zv 1.1.1.1 443", kernel_stopped: "/usr/bin/nc" });
    expect(html).toContain(`data-final-outcome="kernel_stopped"`);
    expect(html).toContain(`>${KERNEL_STOPPED_OUTCOME}</span>`);
    expect(html).not.toContain(">Allowed<");
    expect(html).not.toContain("Allowed to run");
    expect(html).toContain("The kernel stopped nc at exec; the rule engine had allowed it.");
  });

  it("says what came before in the verdict's own words", () => {
    expect(kernelStoppedDetail({ recommendation: "deny", decided_by: "warden" }, "/usr/bin/curl")).toBe("The kernel stopped curl at exec; the on-device Warden had judged it unsafe.");
    expect(kernelStoppedDetail({ recommendation: "review", decided_by: "graph" }, "wget")).toBe("The kernel stopped wget at exec; the session graph had flagged it for review.");
    expect(kernelStoppedDetail({ recommendation: "allow", decided_by: "unknown" }, "nc")).toBe("The kernel stopped nc at exec; the guardrail had allowed it.");
    expect(kernelStoppedDetail({ recommendation: undefined, decided_by: "rules" }, "nc")).toBe("The kernel stopped nc at exec.");
  });

  it("leaves a decision the kernel did not touch as it was", () => {
    const html = render(allowed);
    expect(html).toContain(">Allowed<");
    expect(html).toContain("Allowed to run");
    expect(html).not.toContain(KERNEL_STOPPED_OUTCOME);
  });
});
