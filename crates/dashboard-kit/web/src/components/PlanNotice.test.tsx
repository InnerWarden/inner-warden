import { renderToStaticMarkup } from "react-dom/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PlanNotice as Notice } from "../api/v1";
import { planStep, type PlanView } from "../plan";
import { pinZone } from "../test-support/zone";
import { PlanNotice } from "./PlanNotice";
import { CopyIdButton } from "./TruncatedId";

let restoreZone: () => void = () => undefined;
beforeAll(() => {
  restoreZone = pinZone("UTC");
});
afterAll(() => restoreZone());

const READ_AT = Date.parse("2026-10-23T14:02:00Z");
const DASHES = new RegExp(`[${String.fromCharCode(0x2013)}${String.fromCharCode(0x2014)}]`);
const PLAN_WORDS = /Free mode|licence|Licence|Next step|Hide/;

function render(view: PlanView, onHide?: () => void): string {
  return renderToStaticMarkup(<PlanNotice view={view} onHide={onHide} />);
}

const free: Notice = { state: "free_mode", line: "The host sentence, as sent.", step: "fixture-licence renew", since: "2026-07-30T09:00:00Z" };
const soon: Notice = { state: "ending_soon", line: "The host says it ends soon.", until: "2026-11-06T00:00:00Z" };

describe("PlanNotice", () => {
  it("draws nothing for none", () => {
    expect(render({ kind: "none" })).toBe("");
  });

  it("draws free mode with the host's line and step, a copy button, and no Hide", () => {
    const html = render({ kind: "free_mode", notice: free }, () => undefined);
    expect(html).toContain('data-plan-state="free_mode"');
    // The live region is the shell's wrapper, there before any notice.
    expect(html).not.toContain('role="status"');
    expect(html).toContain('aria-labelledby="plan-notice-title"');
    expect(html).toContain("Free mode since 30 Jul 2026");
    expect(html).toContain("The host sentence, as sent.");
    expect(html).toContain("Next step:");
    expect(html).toContain("<code");
    expect(html).toContain('aria-label="Copy command: fixture-licence renew"');
    expect(html).not.toContain("Hide");
  });

  it("says Free mode alone when the host did not say since when", () => {
    const html = render({ kind: "free_mode", notice: { state: "free_mode", line: "Sent." } });
    expect(html).toContain(">Free mode<");
    expect(html).not.toContain("Next step:");
  });

  it("draws ending soon with the end date and Hide", () => {
    const html = render({ kind: "ending_soon", notice: soon }, () => undefined);
    expect(html).toContain('data-plan-state="ending_soon"');
    expect(html).toContain("The licence ends on 6 Nov 2026");
    expect(html).toContain("Hide");
    expect(render({ kind: "ending_soon", notice: { state: "ending_soon", line: "Sent." } })).toContain("The licence ends soon");
  });

  it("confirms a renewal without saying anything is back on", () => {
    const html = render({ kind: "renewed", readAt: READ_AT }, () => undefined);
    expect(html).toContain('data-plan-state="renewed"');
    expect(html).toMatch(/Licence valid again, read at (23 Oct 2026, )?14:02 UTC\./);
    expect(html).toContain("Each control shows its own state on Protection.");
    expect(html).toContain("Hide");
    expect(html).not.toMatch(/back on|restored|protected|re-?enabled/i);
  });

  it("says a licence state that was not read in the slate box, with the host's line and Hide, and never free mode", () => {
    const html = render({ kind: "unknown", notice: { state: "unknown", line: "The host could not read it." } }, () => undefined);
    expect(html).toContain('data-plan-state="unknown"');
    expect(html).toContain("Licence state not read");
    expect(html).toContain("The host could not read it.");
    expect(html).toContain("border-slate-200");
    expect(html).toContain("Hide");
    expect(html).not.toMatch(/free mode/i);
  });

  it("draws a partial grant in the amber box with the host's line and step", () => {
    const html = render({ kind: "partly_covered", notice: { state: "partly_covered", line: "Sent.", step: "fixture-licence renew" } }, () => undefined);
    expect(html).toContain("Some paid functions are off");
    expect(html).toContain("Sent.");
    expect(html).toContain("Next step:");
    expect(html).toContain("border-amber-200");
  });

  it("draws the kit's own title when the host's line was not usable", () => {
    const html = render({ kind: "free_mode", notice: { state: "free_mode" } });
    expect(html).toContain(">Free mode<");
    expect(html).not.toContain("undefined");
  });

  it("says no plan words for absent or active, and only after a move to active says it is valid again", () => {
    const t = READ_AT;
    for (const state of [undefined, "active"] as const) {
      const { view } = planStep("enterprise", state === undefined ? undefined : { state, line: "Sent." }, {}, t);
      expect(render(view)).not.toMatch(PLAN_WORDS);
    }
    const first = planStep("enterprise", free, {}, t);
    const renewed = planStep("enterprise", { state: "active", line: "Sent." }, first.memory, t + 60_000);
    expect(render(renewed.view)).toContain("Licence valid again");
  });

  it("draws nothing for a Community shell, whatever the bootstrap carries", () => {
    const { view } = planStep("community", free, {}, READ_AT);
    expect(render(view)).toBe("");
  });

  it("uses no dash a reader could mistake for a range", () => {
    for (const view of [
      { kind: "free_mode", notice: free },
      { kind: "ending_soon", notice: soon },
      { kind: "unknown", notice: { state: "unknown", line: "Sent." } },
      { kind: "partly_covered", notice: { state: "partly_covered", line: "Sent." } },
      { kind: "renewed", readAt: READ_AT },
    ] as PlanView[]) {
      expect(render(view, () => undefined)).not.toMatch(DASHES);
    }
  });
});

describe("PlanNotice west of UTC", () => {
  let restore: () => void = () => undefined;
  beforeAll(() => {
    restore = pinZone("America/Los_Angeles");
  });
  afterAll(() => restore());

  /**
   * The host's sentence names the UTC day; the title names the same day for
   * a reader west of UTC, where local midnight is the day before. FAILS ON
   * REVERT to the reader's own zone ("5 Nov 2026").
   */
  it("names the UTC day the host's sentence names", () => {
    expect(render({ kind: "ending_soon", notice: soon })).toContain("The licence ends on 6 Nov 2026");
    expect(render({ kind: "free_mode", notice: { state: "free_mode", line: "Sent.", since: "2026-07-30T00:00:00Z" } })).toContain("Free mode since 30 Jul 2026");
  });
});

describe("CopyIdButton's label", () => {
  it("still says full id by default, byte for byte", () => {
    expect(renderToStaticMarkup(<CopyIdButton value="case:x" />)).toContain('aria-label="Copy full id: case:x"');
  });

  it("names what it copies when told", () => {
    expect(renderToStaticMarkup(<CopyIdButton value="a b" label="command" />)).toContain('aria-label="Copy command: a b"');
  });
});
