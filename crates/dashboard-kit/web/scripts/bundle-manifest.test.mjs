import assert from "node:assert/strict";
import test from "node:test";
import {
  assertExactAssetRecords,
  assetRecord,
  digestEntries,
} from "./bundle-manifest.mjs";

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
