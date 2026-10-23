import assert from "node:assert/strict";
import test from "node:test";
import { bundleBytes, MAX_CSS_BYTES, MAX_JS_BYTES, overBudget, readManifest } from "./bundle-budget.mjs";

test("the committed bundle fits its JS and CSS ceilings", async () => {
  const sizes = bundleBytes(await readManifest());
  assert.ok(sizes.js > 0, "the manifest lists the JS, so the gate measured something");
  assert.ok(sizes.css > 0, "the manifest lists the CSS, so the gate measured something");
  assert.deepEqual(overBudget(sizes), []);
});

test("a bundle over a ceiling fails, in words that say by how much", () => {
  assert.deepEqual(overBudget({ js: MAX_JS_BYTES + 1, css: MAX_CSS_BYTES }), [`JS is ${MAX_JS_BYTES + 1} bytes, over the ${MAX_JS_BYTES} byte ceiling`]);
  assert.deepEqual(overBudget({ js: 1, css: MAX_CSS_BYTES + 1 }), [`CSS is ${MAX_CSS_BYTES + 1} bytes, over the ${MAX_CSS_BYTES} byte ceiling`]);
  assert.deepEqual(overBudget({ js: MAX_JS_BYTES, css: MAX_CSS_BYTES }), []);
});

test("sums the JS and the CSS a manifest lists, and refuses an asset with no size", () => {
  assert.deepEqual(bundleBytes({ assets: [{ path: "assets/a.js", size: 3 }, { path: "assets/b.js", size: 4 }, { path: "assets/c.css", size: 5 }, { path: "index.html", size: 9 }] }), { js: 7, css: 5 });
  assert.throws(() => bundleBytes({ assets: [{ path: "assets/a.js" }] }));
});
