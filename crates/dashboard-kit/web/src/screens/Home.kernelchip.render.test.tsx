import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { DecisionSummary } from "../api";
import { kernelStopped, kernelStoppedLabel, RecentActivity } from "./Home";

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
