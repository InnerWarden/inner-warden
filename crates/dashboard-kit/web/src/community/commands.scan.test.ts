import { describe, expect, it } from "vitest";
import { FIXED_COMMANDS } from "./words";

/**
 * Every product command a Community page prints, held to the one list the
 * CLI's own test reads (`FIXED_COMMANDS`, checked by
 * `dashboard_fixed_commands_are_real_cli_verbs` against the verbs and flags
 * the binary answers). A command written anywhere else is a command that
 * check never sees: a typo in it ships.
 *
 * The scan reads each source file (tests left out), drops comment lines, and
 * collects every string literal and every bit of JSX text that starts with
 * "innerwarden ". Each must be in `FIXED_COMMANDS`, or be named below with
 * the reason it is not there.
 */
const SOURCES = import.meta.glob(["./**/*.ts", "./**/*.tsx", "!./**/*.test.ts", "!./**/*.test.tsx"], {
  query: "?raw",
  eager: true,
  import: "default",
}) as Record<string, string>;

/** Commands printed that are not this CLI's fixed commands, each with why. */
const NOT_FIXED: Record<string, string> = {
  // A prefix the restart rules match a command against, never printed as a step.
  "innerwarden agents connect": "restart.ts: the prefix of every agent connect, matched, not printed",
  "innerwarden agents connect --all": "restart.ts: the prefix of a connect for every agent, matched, not printed",
  "innerwarden install": "restart.ts: a prefix the restart rules match, not printed as a step",
  // Inside a sentence the person adds to their own shell: its last word is
  // the agent's own command, which no CLI usage lists.
  "innerwarden contain --identity -- claude": "controls.ts: the alias line `innerwarden setup` offers, inside a sentence",
  // The host's own command, printed where the paid edition is installed: it
  // is not a verb of this CLI.
  "innerwarden get status": "offers.ts: the host's command, not this CLI's",
};

function withoutComments(source: string): string {
  return source
    .split("\n")
    .filter((line) => !/^\s*(\/\/|\/\*|\*)/.test(line))
    .join("\n");
}

/** Every "innerwarden ..." a source prints, from a string literal or JSX text. */
export function printedCommands(source: string): string[] {
  const code = withoutComments(source);
  const found: string[] = [];
  for (const match of code.matchAll(/(["'`])(innerwarden [^"'`$]*?)\1/g)) found.push(match[2]);
  for (const match of code.matchAll(/>(innerwarden [^<{]*?)</g)) found.push(match[1].trim());
  return found;
}

describe("the commands the pages print", () => {
  it("reads the sources, not nothing", () => {
    const files = Object.keys(SOURCES);
    expect(files.length).toBeGreaterThan(20);
    expect(files.some((file) => file.endsWith("verdict.ts"))).toBe(true);
    expect(files.some((file) => file.includes(".test."))).toBe(false);
  });

  /**
   * FAILS ON REVERT: write `innerwarden agents connect --al --monitor` (a
   * typo) in any page and it is not a fixed command, so this names it.
   */
  it("prints only commands the CLI's own test checks, or names why not", () => {
    const fixed = new Set<string>(FIXED_COMMANDS);
    const strays: string[] = [];
    let seen = 0;
    for (const [file, source] of Object.entries(SOURCES)) {
      for (const command of printedCommands(source)) {
        seen += 1;
        if (!fixed.has(command) && NOT_FIXED[command] === undefined) strays.push(`${file}: ${command}`);
      }
    }
    expect(seen).toBeGreaterThan(30);
    expect(strays).toEqual([]);
  });

  it("would catch a typo, in a string and in JSX text", () => {
    expect(printedCommands('const x = "innerwarden agents connect --al --monitor";')).toEqual(["innerwarden agents connect --al --monitor"]);
    expect(printedCommands("<Code>innerwarden alow --list</Code>")).toEqual(["innerwarden alow --list"]);
    expect(printedCommands('// "innerwarden not printed"')).toEqual([]);
  });

  it("names no exception that is never printed", () => {
    const printed = new Set(Object.values(SOURCES).flatMap(printedCommands));
    for (const command of Object.keys(NOT_FIXED)) expect(printed.has(command), command).toBe(true);
  });
});
