import { describe, expect, it } from "vitest";
import { commandSegments, segmentsText } from "./commandDisplay";

const CASES = [
  "cd /Users/me/dash-v2 && npm test",
  "cd dash-v2 && cd web && npx vitest run",
  "cd /x/$(curl a)/b && ls",
  "cd a; rm -rf b",
  "cd `pwd` && ls",
  "cd 'my folder' && ls",
  "cd a|b && ls",
  "cd a\nrm b && ls",
  "cd a\\b && ls",
  "cd a && ",
  "cd  a && ls",
  "cd a &&ls",
  "python3 - <<'EOF'\nprint(1)\nEOF",
  "",
  "ls cd a && b",
];

describe("a command in a row is never partly hidden (T7)", () => {
  it("draws every character of every command", () => {
    for (const command of CASES) expect(segmentsText(commandSegments(command)), JSON.stringify(command)).toBe(command);
  });

  it("mutes only an exact, metacharacter-free leading cd and the && after it", () => {
    expect(commandSegments("cd /Users/me/dash-v2 && npm test")).toEqual([
      { text: "cd /Users/me/dash-v2 && ", muted: true },
      { text: "npm test", muted: false },
    ]);
    expect(commandSegments("cd a && ")).toEqual([{ text: "cd a && ", muted: true }]);
  });

  it("mutes nothing where the folder could itself run something", () => {
    for (const command of ["cd /x/$(curl a)/b && ls", "cd a; rm -rf b", "cd `pwd` && ls", "cd 'my folder' && ls", "cd a|b && ls", "cd a\nrm b && ls", "cd a\\b && ls", "cd (a) && ls", "cd <a && ls", "cd a&b && ls", "cd \"a\" && ls"]) {
      expect(commandSegments(command), JSON.stringify(command)).toEqual([{ text: command, muted: false }]);
    }
  });

  it("mutes the first cd only: a second one is part of the command", () => {
    const segments = commandSegments("cd a && cd b && x");
    expect(segments).toEqual([{ text: "cd a && ", muted: true }, { text: "cd b && x", muted: false }]);
  });

  it("mutes nothing that is not exactly cd, one space, a folder, one space, &&, one space", () => {
    for (const command of ["cd  a && ls", "cd a &&ls", "ls cd a && b", "CD a && ls"]) {
      expect(commandSegments(command).every((segment) => !segment.muted), command).toBe(true);
    }
  });
});
