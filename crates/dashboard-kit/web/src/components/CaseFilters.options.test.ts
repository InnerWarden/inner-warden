import { describe, expect, it } from "vitest";

/**
 * A filter option that the host can never satisfy is worse than a missing one:
 * it returns zero results and reads as "there are none of those" rather than
 * "that is not a thing here". Three of them shipped at once (`resource` on
 * Scope type, `mixed` on Mode, and a hand-written Authority list missing the two
 * commonest producers), so this file guards the shape of the mistake rather
 * than the individual values.
 *
 * The Rust side owns the harder half: `case_filter_modes_are_exactly_the_modes_a
 * _projector_can_produce` and `case_filter_authorities_are_the_ones_events_
 * really_carry` in the agent check these options against what the host actually
 * produces. This file checks the half that lives entirely here: that the array
 * a value is VALIDATED against and the options a person can SEE cannot drift
 * apart.
 */
// Vite's raw import keeps this typechecking under the web tsconfig, where
// node:fs is deliberately not in scope.
const sources = import.meta.glob("./CaseFilters.tsx", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;
const source = Object.values(sources)[0] ?? "";

function validationArray(name: string): string[] {
  const match = source.match(
    new RegExp(`const ${name} = \\[([^\\]]*)\\] as const`),
  );
  if (!match) throw new Error(`no validation array named ${name}`);
  return [...match[1].matchAll(/"([a-z_0-9-]+)"/g)].map((m) => m[1]);
}

function literalOptions(): string[] {
  return [...source.matchAll(/<option value="([a-z_0-9-]+)"/g)].map((m) => m[1]);
}

describe("case filter options", () => {
  /**
   * Everything below scans `source`. If the raw import ever resolves to nothing,
   * every scan finds nothing and every assertion passes while checking
   * absolutely nothing, which is the failure mode these tests exist to prevent
   * in the product. So prove the file was read before trusting a single pass.
   */
  it("actually read the component it claims to check", () => {
    expect(source.length).toBeGreaterThan(2000);
    expect(source).toContain("const scopeKinds =");
    expect(source).toContain('label="Scope type"');
  });

  /**
   * THE BUG THIS CAUGHT, AFTER THE FIX WAS ALREADY BELIEVED DONE. `resource`
   * was removed from the `scopeKinds` array and left behind as a literal
   * `<option value="resource">`, so the dropdown still offered it and the
   * "fix" changed nothing on screen. Worse than before, in fact: `selected()`
   * validates the URL parameter against the array, so choosing Resource now
   * silently fell back to "all" on reload.
   */
  it.each(["scopeKinds", "windows"])(
    "%s validates no value the operator cannot see",
    (name) => {
      const rendered = literalOptions();
      expect(
        validationArray(name).filter((value) => !rendered.includes(value)),
        `${name} accepts values that appear in no dropdown, so they are only ` +
          `reachable by hand-editing the URL`,
      ).toEqual([]);
    },
  );

  it("scope type offers no option outside its validation array", () => {
    const validated = validationArray("scopeKinds");
    // The scope-type select is the block between its own label and the next.
    const block = source.slice(
      source.indexOf('label="Scope type"'),
      source.indexOf("Scope identifier"),
    );
    const offered = [...block.matchAll(/<option value="([a-z_0-9-]+)"/g)].map(
      (m) => m[1],
    );
    expect(offered.length).toBeGreaterThan(0);
    expect(
      offered.filter((option) => !validated.includes(option)),
      "an option the operator can see but the URL parser will reject, so it " +
        "silently falls back to the default on reload",
    ).toEqual([]);
  });

  it("mode and outcome render from their arrays, so they cannot drift", () => {
    for (const name of ["outcomes", "severities", "modes"]) {
      expect(source, `${name} must render via .map so the array stays the only source`).toContain(
        `${name}.map(`,
      );
    }
  });
});
