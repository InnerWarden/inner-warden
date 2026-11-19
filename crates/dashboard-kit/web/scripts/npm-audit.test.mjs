import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  advisoryId,
  compareVersions,
  entryState,
  isEntry,
  judge,
  main,
  versionsIn,
  wellFormed,
} from "./npm-audit.mjs";

const self = fileURLToPath(new URL("./npm-audit.mjs", import.meta.url));
const PICO = "GHSA-fc5q-39xc-vjpf";
// The waiver the tests run with: a fixture, so the real list in npm-audit.mjs
// can be empty without the tests losing the waived cases.
const WAIVERS = { [PICO]: { package: "picomatch", lastAffected: "4.0.7" } };

const advisory = (name, id, severity) => ({
  name,
  severity,
  title: `${name} issue`,
  url: `https://github.com/advisories/${id}`,
});

const report = (...vias) => ({
  vulnerabilities: Object.fromEntries(
    vias.map((via, i) => [`pkg${i}`, { via: [via, "parent-only-entry"] }]),
  ),
  metadata: { vulnerabilities: { high: vias.length } },
});

const tree = (deps) => JSON.stringify({ name: "web", dependencies: deps });

/** An npm that answers what a test says, and records nothing else. */
const fakeNpm = ({
  audit = JSON.stringify(report(advisory("picomatch", PICO, "high"))),
  installed = tree({ vite: { version: "6.4.6", dependencies: { picomatch: { version: "4.0.7" } } } }),
  shipped = tree({}),
  latest = "4.0.7",
} = {}) => ({
  audit: () => (audit instanceof Error ? (() => { throw audit; })() : audit),
  tree: (_name, omitDev) => (omitDev ? shipped : installed),
  latest: () => (latest instanceof Error ? (() => { throw latest; })() : latest),
});

const runMain = (io) => {
  const out = [];
  const err = [];
  const code = main(io, (l) => out.push(l), (l) => err.push(l), WAIVERS);
  return { code, out, err };
};

test("an advisory not waived fails", () => {
  const { failing, stale } = judge(report(advisory("left-pad", "GHSA-aaaa-bbbb-cccc", "high")), {});
  assert.deepEqual(failing.map((f) => f.id), ["GHSA-aaaa-bbbb-cccc"]);
  assert.deepEqual(stale, []);
});

test("a waiver matches the ID and the package, not the ID alone", () => {
  const r = report(advisory("picomatch", PICO, "high"), advisory("other", PICO, "high"));
  assert.deepEqual(judge(r, WAIVERS).failing.map((f) => f.package), ["other"]);
});

test("below moderate is not a failure, as with --audit-level=moderate", () => {
  assert.deepEqual(judge(report(advisory("tiny", "GHSA-gggg-hhhh-iiii", "low")), {}).failing, []);
});

test("an unknown severity counts as the worst", () => {
  assert.equal(judge(report(advisory("odd", "GHSA-jjjj-kkkk-mmmm", "weird")), {}).failing.length, 1);
});

test("a waiver whose advisory left the tree is reported stale", () => {
  assert.deepEqual(judge(report(), WAIVERS).stale, Object.keys(WAIVERS));
});

test("advisory IDs, versions and trees are read as written", () => {
  assert.equal(advisoryId(`https://github.com/advisories/${PICO}`), PICO);
  assert.equal(compareVersions("4.0.7", "4.0.7"), 0);
  assert.equal(compareVersions("4.0.10", "4.0.7"), 1);
  assert.ok(Number.isNaN(compareVersions("4.0.8-rc.1", "4.0.7")));
  const t = JSON.parse(tree({ a: { version: "1.0.0", dependencies: { picomatch: { version: "2.3.1" } } }, picomatch: { version: "4.0.7" } }));
  assert.deepEqual(versionsIn(t, "picomatch").sort(), ["2.3.1", "4.0.7"]);
});

test("a report without the fields it needs is not well formed", () => {
  assert.ok(wellFormed(report()));
  for (const bad of [{}, { vulnerabilities: {} }, { metadata: { vulnerabilities: {} } }, null, [],
    { vulnerabilities: { x: {} }, metadata: { vulnerabilities: {} } }]) {
    assert.equal(wellFormed(bad), false, JSON.stringify(bad));
  }
});

test("main: the waived advisory on a dev-only package at the last affected release passes", () => {
  const { code, out } = runMain(fakeNpm());
  assert.equal(code, 0);
  assert.match(out[0], /1 waived/);
});

test("main: output that is not JSON fails", () => {
  const { code, err } = runMain(fakeNpm({ audit: "npm WARN something\n" }));
  assert.equal(code, 1);
  assert.match(err[0], /could not be read/);
});

test("main: npm that could not run fails", () => {
  assert.equal(runMain(fakeNpm({ audit: new Error("ENOENT") })).code, 1);
});

test("main: an npm error report fails", () => {
  const { code, err } = runMain(fakeNpm({ audit: JSON.stringify({ error: { code: "ENOLOCK" } }) }));
  assert.equal(code, 1);
  assert.match(err[0], /ENOLOCK/);
});

test("main: a report of unknown shape fails rather than passing as empty", () => {
  for (const audit of ["{}", JSON.stringify({ auditReportVersion: 2, vulnerabilities: {} })]) {
    assert.equal(runMain(fakeNpm({ audit })).code, 1, audit);
  }
});

test("main: a registry that does not answer fails", () => {
  const { code, err } = runMain(fakeNpm({ latest: new Error("ETIMEDOUT") }));
  assert.equal(code, 1);
  assert.match(err.join("\n"), /registry did not say/);
});

test("main: a release past the last affected one fails", () => {
  assert.equal(runMain(fakeNpm({ latest: "4.0.8" })).code, 1);
});

test("main: an installed copy past the last affected release is not waived", () => {
  const installed = tree({ picomatch: { version: "4.0.8" } });
  const { code, err } = runMain(fakeNpm({ installed }));
  assert.equal(code, 1);
  assert.match(err.join("\n"), /past the last affected/);
});

test("main: a waived package that ships at runtime is not waived", () => {
  const shipped = tree({ react: { version: "19.0.0", dependencies: { picomatch: { version: "4.0.7" } } } });
  const { code, err } = runMain(fakeNpm({ shipped }));
  assert.equal(code, 1);
  assert.match(err.join("\n"), /runtime dependency/);
});

test("main: a waiver left behind after the advisory went fails", () => {
  const { code, err } = runMain(fakeNpm({ audit: JSON.stringify(report()) }));
  assert.equal(code, 1);
  assert.match(err.join("\n"), /no longer matches/);
});

test("a path to this script that cannot be resolved fails the gate instead of skipping it", () => {
  const dir = mkdtempSync(join(tmpdir(), "npm-audit-unresolved-"));
  try {
    // A dangling link named like the script: realpath fails on it.
    const dangling = join(dir, "npm-audit.mjs");
    symlinkSync(join(dir, "gone.mjs"), dangling);
    assert.equal(entryState(dangling), "unresolved");
    assert.equal(isEntry(dangling), false);
    // Another file that cannot be resolved is someone else's: not this gate.
    assert.equal(entryState(join(dir, "missing.mjs")), "other");
    assert.equal(entryState(self), "entry");
    assert.equal(entryState(undefined), "other");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the script runs when reached through a symlink, and only then is it the entry", () => {
  const dir = mkdtempSync(join(tmpdir(), "npm-audit-link-"));
  try {
    const link = join(dir, "audit-link.mjs");
    symlinkSync(self, link);
    assert.equal(isEntry(link), true);
    assert.equal(isEntry(self), true);
    assert.equal(isEntry(join(dir, "missing.mjs")), false);
    assert.equal(isEntry(undefined), false);
    assert.equal(isEntry(self.toUpperCase(), self, "win32") || isEntry(self, self, "win32"), true);
    // Run for real through the link: before the fix this printed nothing and
    // exited 0. Whatever the verdict, main() must have said something.
    let output;
    try {
      output = execFileSync(process.execPath, [link], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      output = `${e.stdout}${e.stderr}`;
    }
    assert.match(output, /npm audit|advisory|waiver/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
