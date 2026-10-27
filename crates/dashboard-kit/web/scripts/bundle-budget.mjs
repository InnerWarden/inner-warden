import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The size the Community bundle may reach, checked on the manifest the build
 * writes (`dist/bundle-manifest.json`, whose sizes `bundle:check` holds to the
 * files). A ceiling a gate never reads is a ceiling nobody keeps: this one is
 * read by `npm run test:bundle`, which CI runs.
 *
 * Raising a ceiling is a decision, made here on purpose with its reason in
 * the commit, never by a build that happens to be larger.
 *
 * JS: 610,000 bytes. The v2 pages measured 606,403 at the end of the review
 * pass that added this gate, above the 590,000 first planned for v2; the
 * difference is listed for a later trim.
 * CSS: 56,000 bytes.
 */
export const MAX_JS_BYTES = 610_000;
export const MAX_CSS_BYTES = 56_000;

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** The JS and CSS bytes a manifest lists, summed by kind. */
export function bundleBytes(manifest) {
  let js = 0;
  let css = 0;
  for (const asset of manifest.assets ?? []) {
    if (typeof asset.size !== "number") throw new Error(`manifest asset without a size: ${asset.path}`);
    if (asset.path.endsWith(".js")) js += asset.size;
    else if (asset.path.endsWith(".css")) css += asset.size;
  }
  return { js, css };
}

/** What is over its ceiling, in words; empty when the bundle fits. */
export function overBudget({ js, css }, limits = { js: MAX_JS_BYTES, css: MAX_CSS_BYTES }) {
  const over = [];
  if (js > limits.js) over.push(`JS is ${js} bytes, over the ${limits.js} byte ceiling`);
  if (css > limits.css) over.push(`CSS is ${css} bytes, over the ${limits.css} byte ceiling`);
  return over;
}

export async function readManifest() {
  return JSON.parse(await readFile(join(webRoot, "dist", "bundle-manifest.json"), "utf8"));
}
