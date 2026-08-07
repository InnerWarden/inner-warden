import { describe, expect, it } from "vitest";

/**
 * The editorial guard.
 *
 * The dashboard is read by someone who wants to know how their machine is and,
 * when something happened, to dig into it. Copy that describes OUR plumbing
 * instead of THEIR host fails that test, and it kept coming back: adapters,
 * bootstraps, projections, contracts, counters of our own records, and
 * permanent disclaimers rendered on every load until they stop being read.
 *
 * Every honesty rule survives; each retired line below was replaced by one that
 * says the same true thing in the user's language, or moved one click down.
 * This file is where that stays decided, because prose has no type checker.
 */

/**
 * Every `.tsx` under `src`, which is everything that renders.
 *
 * Read through Vite rather than `node:fs` so the guard needs no node types and
 * cannot drift from the module graph the bundle is actually built from.
 */
const SOURCES: Record<string, string> = import.meta.glob("./**/*.tsx", {
  query: "?raw",
  eager: true,
  import: "default",
});

/**
 * The file with its comments removed.
 *
 * The comments in these files quote the copy they replaced, on purpose, so a
 * later reader knows what was wrong with it. A raw scan would read those
 * epitaphs as the copy still shipping.
 */
export function withoutComments(source: string): string {
  let out = "";
  let index = 0;
  let mode: "code" | "line" | "block" | "single" | "double" | "template" = "code";
  while (index < source.length) {
    const character = source[index];
    const next = source[index + 1];
    if (mode === "code") {
      if (character === "/" && next === "/") { mode = "line"; index += 2; continue; }
      if (character === "/" && next === "*") { mode = "block"; index += 2; continue; }
      if (character === "'") mode = "single";
      else if (character === '"') mode = "double";
      else if (character === "`") mode = "template";
      out += character;
      index += 1;
      continue;
    }
    if (mode === "line") {
      if (character === "\n") { mode = "code"; out += character; }
      index += 1;
      continue;
    }
    if (mode === "block") {
      if (character === "*" && next === "/") { mode = "code"; index += 2; continue; }
      // Keep newlines so a finding still reports a plausible line number.
      if (character === "\n") out += character;
      index += 1;
      continue;
    }
    // Inside a string literal: a backslash escapes whatever follows.
    if (character === "\\") { out += character + (next ?? ""); index += 2; continue; }
    if ((mode === "single" && character === "'") || (mode === "double" && character === '"') || (mode === "template" && character === "`")) {
      mode = "code";
    }
    out += character;
    index += 1;
  }
  return out;
}

/**
 * Copy that shipped, and must not come back.
 *
 * Each entry is verbatim from the source it was removed from, so this list can
 * only be satisfied by the replacement and never by a paraphrase of the
 * original.
 */
const RETIRED: [string, string][] = [
  ["Outcomes reported by newer guardrail integrations", "which of our integrations are new is not a fact about the host"],
  ["Local rule analysis", "the three trust lines were a permanent strip on every load"],
  ["Read-only dashboard API", "an API property, written as a user benefit"],
  ["Included, not gated", "a brochure printed on the instrument"],
  ["Privacy by design:", "a coloured banner above the numbers on every load"],
  ["Privacy boundary:", "the same banner, on the other token screen"],
  ["Producer-reported", "a standing property of every case, styled as a status to act on"],
  ["Feedback writes remain unavailable", "our roadmap is not the user's business"],
  ["Events remain separately typed", "a description of the schema, not of the case"],
  ["Context only: this record does not establish causation.", "printed inside every contextual event; now one legend"],
  ["The relationship to adjacent events is unknown.", "printed inside every unknown event; now one legend"],
  ["Resolving a validated dashboard v1 bootstrap", "the first sentence a user can see, written for the wire"],
  ["v1 adapter unavailable", "adapter language in a status badge"],
  ["The validated bootstrap did not declare this capability", "adapter language on an empty screen"],
  ["Missing or unsupported counters remain unavailable", "explains our rule instead of offering the next step"],
  ["Suggested checks", "a count of chips printed in full underneath it"],
  ["The board beside this", "the board moved below the chart and this kept pointing sideways"],
  ["This is a producer fault, not an empty host", "producer is our word, not theirs"],
  ["Read-only projection", "projection is a contract word"],
  ["Unsupported server dimensions", "our plumbing on every load, for a case that mostly does not apply"],
];

/** Copy that replaced it, and must still be there. */
const REQUIRED: string[] = [
  "How this dashboard handles your data",
  "What the guardrail actually did",
  "What Community includes",
  "Connecting to InnerWarden on this machine",
  "is not part of this installation",
  "Who decided what",
  "When it happened",
  "kept in the address bar",
];

describe("the dashboard speaks to the person using it", () => {
  const sources = Object.entries(SOURCES)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([path, text]) => ({ path, text: withoutComments(text) }));

  it("scans every rendering source, so the guard cannot be vacuous", () => {
    expect(sources.length).toBeGreaterThan(10);
    expect(sources.some(({ path }) => path.endsWith("Home.tsx"))).toBe(true);
    expect(sources.some(({ path }) => path.endsWith("CapabilityBoundary.tsx"))).toBe(true);
  });

  it.each(RETIRED)("does not ship %s", (phrase, why) => {
    const offenders = sources.filter(({ text }) => text.includes(phrase)).map(({ path }) => path);
    expect(`${phrase} in ${offenders.join(", ")} (${why})`).toBe(`${phrase} in  (${why})`);
  });

  it.each(REQUIRED)("still says %s", (phrase) => {
    expect(sources.some(({ text }) => text.includes(phrase))).toBe(true);
  });

  /**
   * The stripper itself, because a broken one would make every assertion above
   * pass by accident.
   */
  it("removes comments and leaves strings alone", () => {
    expect(withoutComments('const a = "keep"; // drop\nconst b = 1;')).toBe('const a = "keep"; \nconst b = 1;');
    expect(withoutComments("/* drop */const c = 2;")).toBe("const c = 2;");
    expect(withoutComments('const url = "https://example.test/a";')).toBe('const url = "https://example.test/a";');
    expect(withoutComments('const quoted = "a // b";')).toBe('const quoted = "a // b";');
    expect(withoutComments("const t = `a /* b */ c`;")).toBe("const t = `a /* b */ c`;");
    expect(withoutComments('const e = "a\\"// b";')).toBe('const e = "a\\"// b";');
  });
});

describe("token surfaces keep the not-a-score limit", () => {
  // REGRESSION ANCHOR. An editorial pass dropped "not a security score" from
  // both token surfaces. That limit is a claim boundary: token counts explain
  // activity, and presenting them without the limit invites reading them as a
  // risk metric. The only prior enforcement was a browser test that the same
  // pass turned red without noticing; this pins it at unit level.
  it("both token footnotes carry the limit", async () => {
    const { readFileSync } = await import("node:fs");
    for (const file of [
      "src/screens/TokenIntelligence.tsx",
      "src/components/MachineIntelligence.tsx",
    ]) {
      const text = readFileSync(file, "utf8");
      expect(text, `${file} must say the counts are not a security score`).toContain(
        "not a security score",
      );
    }
  });
});
