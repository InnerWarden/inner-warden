import assert from "node:assert/strict";
import test from "node:test";
import {
  assertExactAssetRecords,
  assetRecord,
  byCodeUnit,
  digestEntries,
} from "./bundle-manifest.mjs";

/**
 * REGRESSION ANCHOR.
 *
 * `assets.rs` rejects a manifest whose asset list is not sorted by byte order,
 * and the embedded bundle is then refused wholesale — a dashboard that will not
 * serve. This file used to sort with `localeCompare`, which agrees with byte
 * order for most names and disagrees for some. Which one you get is decided by
 * Vite's content hash, so the failure arrives on a random build with no source
 * change to blame it on: the pair below is the one that actually did it.
 */
test("asset ordering matches the byte order the Rust validator requires", () => {
  const emitted = ["assets/index-_wt4hCb1.css", "assets/index-CmaS9UlA.js", "index.html"];
  const sorted = [...emitted].sort(byCodeUnit);
  assert.deepEqual(sorted, ["assets/index-CmaS9UlA.js", "assets/index-_wt4hCb1.css", "index.html"]);
  // Byte order, not the host's collation. Every adjacent pair must satisfy the
  // same `<` the validator applies.
  for (let index = 1; index < sorted.length; index += 1) assert.ok(sorted[index - 1] < sorted[index]);
});

test("source fingerprint does not depend on the host's collation", () => {
  const inputs = [
    { name: "src/_leading-underscore.ts", contents: "a\n" },
    { name: "src/Capital.ts", contents: "b\n" },
    { name: "src/lower.ts", contents: "c\n" },
  ];
  const byBytes = [...inputs].sort((left, right) => byCodeUnit(left.name, right.name)).map((entry) => entry.name);
  assert.deepEqual(byBytes, ["src/Capital.ts", "src/_leading-underscore.ts", "src/lower.ts"]);
  assert.equal(digestEntries(inputs), digestEntries([...inputs].reverse()));
});

const baseline = [
  { name: "src/App.tsx", contents: "export const App = 1;\n" },
  { name: "index.html", contents: "<main></main>\n" },
];

test("source fingerprint is deterministic across traversal order", () => {
  assert.equal(digestEntries(baseline), digestEntries([...baseline].reverse()));
});

test("source fingerprint changes when a bundled input changes", () => {
  const changed = baseline.map((entry) => ({ ...entry }));
  changed[0].contents = "export const App = 2;\n";
  assert.notEqual(digestEntries(baseline), digestEntries(changed));
});

test("source fingerprint is stable across checkout line endings", () => {
  const crlf = baseline.map((entry) => ({ ...entry, contents: entry.contents.replaceAll("\n", "\r\n") }));
  assert.equal(digestEntries(baseline), digestEntries(crlf));
});

const output = [
  assetRecord("assets/app.js", Buffer.from("import './validate.js';\n")),
  assetRecord("assets/validate.js", Buffer.from("export const valid = true;\n")),
  assetRecord("index.html", Buffer.from("<script src=\"./assets/app.js\"></script>\n")),
];

test("asset inventory rejects altered output content", () => {
  const altered = output.map((entry) => ({ ...entry }));
  altered[0] = assetRecord("assets/app.js", Buffer.from("tampered\n"));
  assert.throws(() => assertExactAssetRecords(output, altered), /asset inventory does not match/);
});

test("asset inventory rejects a missing transitive chunk", () => {
  const missing = output.filter((entry) => entry.path !== "assets/validate.js");
  assert.throws(() => assertExactAssetRecords(output, missing), /asset inventory does not match/);
});

test("asset inventory rejects an unmanifested extra file", () => {
  const extra = [...output, assetRecord("assets/extra.js", Buffer.from("extra\n"))];
  assert.throws(() => assertExactAssetRecords(output, extra), /asset inventory does not match/);
});
