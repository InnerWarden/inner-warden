import { test } from "node:test";
import assert from "node:assert/strict";
import { advisoryId, judge, WAIVERS } from "./npm-audit.mjs";

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
});

test("an advisory not waived fails", () => {
  const r = report(advisory("left-pad", "GHSA-aaaa-bbbb-cccc", "high"));
  const { failing, stale } = judge(r, {});
  assert.deepEqual(failing.map((f) => f.id), ["GHSA-aaaa-bbbb-cccc"]);
  assert.deepEqual(stale, []);
});

test("a waived advisory passes, another one beside it still fails", () => {
  const r = report(
    advisory("picomatch", "GHSA-fc5q-39xc-vjpf", "high"),
    advisory("other", "GHSA-dddd-eeee-ffff", "moderate"),
  );
  const { failing } = judge(r, WAIVERS);
  assert.deepEqual(failing.map((f) => f.id), ["GHSA-dddd-eeee-ffff"]);
});

test("below moderate is not a failure, as with --audit-level=moderate", () => {
  const r = report(advisory("tiny", "GHSA-gggg-hhhh-iiii", "low"));
  assert.deepEqual(judge(r, {}).failing, []);
});

test("an unknown severity counts as the worst", () => {
  const r = report(advisory("odd", "GHSA-jjjj-kkkk-mmmm", "weird"));
  assert.equal(judge(r, {}).failing.length, 1);
});

test("a waiver whose advisory left the tree is reported stale", () => {
  const { stale } = judge({ vulnerabilities: {} }, WAIVERS);
  assert.deepEqual(stale, Object.keys(WAIVERS));
});

test("advisory IDs come from the URL", () => {
  assert.equal(advisoryId("https://github.com/advisories/GHSA-fc5q-39xc-vjpf"), "GHSA-fc5q-39xc-vjpf");
});
