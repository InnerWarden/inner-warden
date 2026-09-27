import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { signedInAccount, signedInLabel } from "./App";
import { Header } from "./components/Header";
import { casePageCountBadge } from "./components/casePageCount";
import { Outcome, OUTCOME_CHIPS } from "./components/Outcome";
import { statusPresentation } from "./components/StatusBadge";
import { formatCount, hasControlCharacters } from "./presentation";
import { agreeWithControls, dispositionReason } from "./screens/Posture";

/**
 * The wording and badge slips a first reader caught, each fixed where the
 * kit prints it.
 */

describe("one way to print a count", () => {
  /**
   * One card printed "1,298" beside "1298", and a count went through the
   * viewer's locale in one panel and a fixed one in the next.
   */
  it("groups thousands the same way for every viewer", () => {
    expect(formatCount(1298)).toBe("1,298");
    expect(formatCount(4_394_000)).toBe("4,394,000");
    expect(formatCount(-0)).toBe("0");
    expect(formatCount(12345678901234567890n)).toBe("12,345,678,901,234,567,890");
  });
});

describe("the count line's badge", () => {
  /**
   * FAILS ON REVERT: wear "available" whatever the read covered and the green
   * check is back on a partial read.
   */
  it("is neutral on a partial read, and never a green check over it", () => {
    const partial = casePageCountBadge(20, { rows_in_window: 312, total_in_window: 4_394, window_complete: false }, false);
    expect(partial.status).toBe("partial");
    expect(partial.label).toContain("(counted from the newest records)");
    expect(statusPresentation(partial.status).tone).toBe("neutral");
    expect(statusPresentation(partial.status).symbol).not.toBe("✓");
  });

  it("is a check on a whole read, and says a list being refreshed is stale", () => {
    expect(casePageCountBadge(20, { rows_in_window: 312, window_complete: true }, false).status).toBe("available");
    expect(casePageCountBadge(20, { rows_in_window: 312, window_complete: false }, true).status).toBe("stale");
    expect(casePageCountBadge(3, { window_complete: false }, false).status).toBe("available");
  });
});

describe("the outcome chip", () => {
  it("says what a one-off check is instead of an unexplained Screened", () => {
    const html = renderToStaticMarkup(<Outcome value="screened" />);
    expect(html).toContain(">Checked only<");
    expect(html).toContain('title="Judged by a one-off check.');
    expect(html).not.toContain(">Screened<");
  });

  it("explains every chip it can draw", () => {
    for (const chip of Object.values(OUTCOME_CHIPS)) expect(chip.meaning.length).toBeGreaterThan(10);
    expect(renderToStaticMarkup(<Outcome value="something_new" />)).toContain(">Outcome unknown<");
  });
});

describe("a control named in the plural", () => {
  it("takes are, in the host's sentence and in the page's own", () => {
    expect(agreeWithControls("Response controls is blocking, and that was verified on this host."))
      .toBe("Response controls are blocking, and that was verified on this host.");
    expect(agreeWithControls("Host visibility is watching.")).toBe("Host visibility is watching.");
    const layer = {
      id: "response_controls",
      capability_ids: ["response_controls"],
      label: "Response controls",
      claim_state: "not_covered" as const,
      effective_mode: "disabled" as const,
      desired_mode: "disabled" as const,
      disposition: "not_enabled" as const,
    };
    expect(dispositionReason(layer)).toBe("Response controls have not been turned on yet. Nothing is wrong.");
  });
});

describe("who is signed in", () => {
  /**
   * A change is "recorded under your name", and the page never showed the
   * name. The badge names it.
   */
  it("names the signed-in person, and says only Signed in about a name it cannot print", () => {
    expect(signedInLabel("alice")).toBe("Signed in as alice");
    expect(signedInLabel(null)).toBe("Signed in");
    expect(signedInLabel("  ")).toBe("Signed in");
    expect(signedInLabel("x".repeat(65))).toBe("Signed in");
    expect(signedInLabel("bad\u0007name")).toBe("Signed in");
    // FAILS ON REVERT: reject C0 and DEL alone, and a C1 control or a right
    // to left override (which reorders the badge's words) is printed.
    expect(signedInLabel("bad\u0085name")).toBe("Signed in");
    expect(signedInLabel("alice\u202Enimda")).toBe("Signed in");
    expect(signedInLabel("\u2066alice\u2069")).toBe("Signed in");
    expect(signedInLabel("zoë.o'brien-ops@example.test")).toBe("Signed in as zoë.o'brien-ops@example.test");
  });

  it("gives the menu the name, and the badge its words on hover", () => {
    const ready = { state: "ready" as const, data: { session: { authenticated: true, actor_id: "alice" } } } as unknown as Parameters<typeof signedInAccount>[0];
    expect(signedInAccount(ready)).toBe("Signed in as alice");
    const signedOut = { state: "ready" as const, data: { session: { authenticated: false, actor_id: null } } } as unknown as Parameters<typeof signedInAccount>[0];
    expect(signedInAccount(signedOut)).toBeUndefined();
    expect(signedInAccount({ state: "loading" })).toBeUndefined();
    const menu = renderToStaticMarkup(
      <Header editionLabel="Enterprise" navigation={[]} activeRoute="overview" homeRoute="overview" onNavigate={() => undefined} status={null} account="Signed in as alice" />,
    );
    // Said in the menu below 400 px, where the badge keeps only its check.
    expect(menu).toMatch(/<p data-header-account="true" class="[^"]*min-\[400px\]:hidden[^"]*">Signed in as alice<\/p>/);
    expect(renderToStaticMarkup(
      <Header editionLabel="Community" navigation={[]} activeRoute="overview" homeRoute="overview" onNavigate={() => undefined} status={null} />,
    )).not.toContain("data-header-account");
  });

  it("names every control or format character as not text", () => {
    for (const bad of ["\u0000", "\u001f", "\u007f", "\u0085", "\u009f", "\u200e", "\u202a", "\u202e", "\u2066", "\u2069", "\ufeff"]) {
      expect(hasControlCharacters(`a${bad}b`), JSON.stringify(bad)).toBe(true);
    }
    expect(hasControlCharacters("plain words, é and 漢字")).toBe(false);
  });
});
