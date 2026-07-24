#!/usr/bin/env node
// Publish the platform packages first, then the main `innerwarden` package.
// Order matters: the main package lists the platform packages as
// optionalDependencies at an exact version, so they must exist on the registry
// first. Scoped packages need --access public on their first publish.
//
// Requires `npm login` (an account that owns the `innerwarden` name and the
// @innerwarden org). Run `node scripts/build.mjs` first.
//
// Usage:  node scripts/publish.mjs [--dry-run]

import { readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "platforms");
const DRY = process.argv.includes("--dry-run");

if (!existsSync(OUT)) {
  process.stderr.write("platforms/ not found. Run `node scripts/build.mjs` first.\n");
  process.exit(1);
}

function publish(dir, extraArgs) {
  const args = ["publish", ...extraArgs];
  if (DRY) args.push("--dry-run");
  process.stdout.write(`\n$ npm ${args.join(" ")}   (cwd ${dir})\n`);
  execFileSync("npm", args, { cwd: dir, stdio: "inherit" });
}

// Platform packages (scoped -> --access public).
for (const name of readdirSync(OUT).sort()) {
  publish(join(OUT, name), ["--access", "public"]);
}

// Main package last.
publish(ROOT, []);

process.stdout.write(DRY ? "\ndry-run complete.\n" : "\npublished. Try: npx innerwarden --version\n");
