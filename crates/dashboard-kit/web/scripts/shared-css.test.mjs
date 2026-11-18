import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { CHANGED_MESSAGE, GROWTH_MESSAGE, measure, sharedStylesheet, verdict } from "./shared-css.mjs";

const baseline = { bytes: 100, sha256: `sha256:${"a".repeat(64)}` };

test("a larger shared stylesheet is growth, said in the gate's own words", () => {
  assert.equal(verdict(baseline, { bytes: 101, sha256: `sha256:${"b".repeat(64)}` }), GROWTH_MESSAGE);
  assert.equal(GROWTH_MESSAGE, "a new utility in a shared file reaches the paid stylesheet: reuse a class a shared file already uses");
});

test("any other difference asks for a written baseline and a reason", () => {
  assert.equal(verdict(baseline, { bytes: 99, sha256: baseline.sha256 }), CHANGED_MESSAGE);
  assert.equal(verdict(baseline, { bytes: 100, sha256: `sha256:${"c".repeat(64)}` }), CHANGED_MESSAGE);
  assert.equal(CHANGED_MESSAGE, "shared stylesheet changed: rewrite the baseline with npm run css:shared -- write and say why in the commit");
});

test("the same stylesheet passes", () => {
  assert.equal(verdict(baseline, { ...baseline }), undefined);
});

test("the measure is the UTF-8 size and the SHA-256 of the text", () => {
  const text = "a::after{content:\"\u00e9\"}";
  assert.deepEqual(measure(text), {
    bytes: Buffer.byteLength(text, "utf8"),
    sha256: `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`,
  });
  assert.equal(measure(text).bytes, text.length + 1, "a two-byte character counts twice");
});

test("the shared stylesheet is built the same way twice", async () => {
  const first = await sharedStylesheet();
  const second = await sharedStylesheet();
  assert.equal(first, second);
  assert.ok(first.length > 1_000, "the shared files produce a stylesheet");
});
