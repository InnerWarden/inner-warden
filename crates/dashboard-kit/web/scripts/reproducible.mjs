#!/usr/bin/env node
// Assert the bundle is byte-identical whether or not a previous build is on disk.
//
// `dist/` is committed, so it is not gitignored, so Tailwind's automatic source
// detection used to scan it and lift class-like strings out of the previous
// build's own JavaScript. Identical sources then produced different bytes on a
// clean tree than on a dirty one. `@source not "../dist"` in `src/index.css` is
// the fix; this is the check that keeps it fixed, because the failure mode is
// invisible to anyone who only ever builds one way.

import { execFileSync } from "node:child_process";
import { readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = join(web, "dist", "bundle-manifest.json");

const build = () => execFileSync("npm", ["run", "build"], { cwd: web, stdio: "ignore" });
const digests = () => {
  const parsed = JSON.parse(readFileSync(manifest, "utf8"));
  return JSON.stringify({
    source: parsed.source_digest,
    assets: parsed.assets.map((asset) => [asset.path, asset.sha256, asset.size]),
  });
};

rmSync(join(web, "dist"), { recursive: true, force: true });
build();
const fromClean = digests();

build();
const fromDirty = digests();

if (fromClean !== fromDirty) {
  console.error("dashboard bundle is NOT reproducible: building over an existing dist/ changed the output");
  console.error(`  clean tree: ${fromClean}`);
  console.error(`  dirty tree: ${fromDirty}`);
  process.exit(1);
}
console.log("dashboard bundle is reproducible (identical from a clean and a dirty tree)");
