import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ENTERPRISE_UNKNOWN_POSTURE, PostureHero } from "./Home";
// The screen's own source, for the wiring assertion at the bottom of this file.
import homeSource from "./Home.tsx?raw";

/**
 * The defect these pin, measured on live.innerwarden.com on 2026-08-31: the
 * hero read "Guardrail decisions not recorded here ... so that counter reads
 * zero" while `/api/guard/overview` answered `commands: 8, deny_verdicts: 5`.
 * The host had already computed the true sentence; the screen preferred a
 * constant keyed on a guardrail mode that reads `unknown` on every paid host.
 *
 * These tests RENDER the component, because the first attempt did not. It
 * rebuilt the merge expression inside the test and asserted on its own object,
 * so it passed with the fix reverted out of the component -- it proved that
 * spreading two objects works. Reverting `PostureHero` to `postureFor(mode,
 * edition)` must make the first test below FAIL, and it does.
 */

const HOST_HEADLINE = {
  label: "Screening agent actions",
  title: "8 agent actions screened on this host.",
  body: "Recorded across 2 sessions. 5 of them were classified deny.",
};

function renderHero(hostHeadline?: { label: string; title: string; body: string }) {
  return renderToStaticMarkup(
    <PostureHero
      mode="unknown"
      edition="enterprise"
      decisions={8}
      sessions={2}
      hostHeadline={hostHeadline}
    />,
  );
}

describe("the hero prints the host's sentence, not its own constant", () => {
  it("renders the host's words when the host sent them", () => {
    const html = renderHero(HOST_HEADLINE);
    expect(html).toContain("8 agent actions screened on this host.");
    expect(html).toContain("5 of them were classified deny.");
    expect(html).toContain("Screening agent actions");
  });

  it("does not render the sentence that contradicted the payload", () => {
    const html = renderHero(HOST_HEADLINE);
    // The exact claim the page made beside a payload carrying 8 screened
    // commands. Its presence here is the production bug, rendered.
    expect(html).not.toMatch(/reads zero/i);
    expect(html).not.toContain(ENTERPRISE_UNKNOWN_POSTURE.title);
  });

  it("keeps the local colours, which are presentation and not facts", () => {
    const html = renderHero(HOST_HEADLINE);
    // `badge` and `panel` are class strings and must survive the merge: the
    // host sends words, never styling.
    expect(html).toContain(ENTERPRISE_UNKNOWN_POSTURE.badge);
    expect(html).toContain(ENTERPRISE_UNKNOWN_POSTURE.panel);
  });

  // The control. An older host sends no headline, and that fleet has to keep
  // rendering its own copy rather than an empty hero.
  it("falls back to its own copy when the host sent nothing", () => {
    const html = renderHero(undefined);
    expect(html).toContain(ENTERPRISE_UNKNOWN_POSTURE.title);
    expect(html).toContain(ENTERPRISE_UNKNOWN_POSTURE.body);
  });

  // The numbers are the screen's own and must not be disturbed by the merge.
  it("still shows the counters it was given", () => {
    const html = renderHero(HOST_HEADLINE);
    expect(html).toContain("Decisions recorded");
    expect(html).toContain("Sessions");
  });
});

/**
 * A component that honours `hostHeadline` is useless if the screen never
 * passes it. `Home` fills `overview` from a `useEffect`, which
 * `renderToStaticMarkup` does not run, so the hero cannot be reached by
 * rendering `Home`. This reads the wiring off the source instead.
 *
 * It is a structural assertion, not a copy assertion: it fails when the prop
 * stops being passed, which is the regression, and it does not care about
 * wording, ordering or formatting elsewhere in the file.
 */
describe("Home wires the host's headline into the hero", () => {
  it("passes overview.headline to PostureHero", () => {
    const call = homeSource.match(/<PostureHero[^>]*\/>/s);
    expect(call, "Home no longer renders PostureHero").not.toBeNull();
    expect(call![0]).toContain("hostHeadline={overview.headline}");
  });
});
