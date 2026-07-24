#!/usr/bin/env node
// Publish the platform packages first, then the main `innerwarden` package.
// Order matters: the main package lists the platform packages as
// optionalDependencies at an exact version, so they must exist on the registry
// first. Scoped packages need --access public on their first publish.
//
// Requires `npm login` (an account that owns the `innerwarden` name and the
// @innerwarden org). Run `node scripts/build.mjs` first.
//
// If the account has 2FA enabled (npm now requires it for publishing), pass a
// fresh one-time code via NPM_OTP. A single code is reused across all packages;
// npm accepts it within its validity window. If it expires part-way through,
// just re-run with a new code: already-published versions are skipped.
//
// Usage:  node scripts/publish.mjs [--dry-run]
//         NPM_OTP=123456 node scripts/publish.mjs

import { readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "platforms");
const DRY = process.argv.includes("--dry-run");
const OTP = process.env.NPM_OTP || "";

if (!existsSync(OUT)) {
  process.stderr.write("platforms/ not found. Run `node scripts/build.mjs` first.\n");
  process.exit(1);
}

function publish(dir, extraArgs) {
  const args = ["publish", ...extraArgs];
  if (OTP) args.push(`--otp=${OTP}`);
  if (DRY) args.push("--dry-run");
  const shown = args.map((a) => (a.startsWith("--otp=") ? "--otp=******" : a));
  process.stdout.write(`\n$ npm ${shown.join(" ")}   (cwd ${dir})\n`);
  try {
    const out = execFileSync("npm", args, { cwd: dir, encoding: "utf8", stdio: ["inherit", "pipe", "pipe"] });
    process.stdout.write(out);
  } catch (err) {
    const combined = ((err.stdout || "") + (err.stderr || "")).toString();
    // Re-runs are safe: a version already on the registry is a success, not a failure.
    if (/cannot publish over|previously published|EPUBLISHCONFLICT|409 Conflict/i.test(combined)) {
      process.stdout.write("  already published at this version, skipping.\n");
      return;
    }
    process.stderr.write(combined);
    throw err;
  }
}

// Platform packages (scoped -> --access public).
for (const name of readdirSync(OUT).sort()) {
  publish(join(OUT, name), ["--access", "public"]);
}

// Main package last.
publish(ROOT, []);

process.stdout.write(DRY ? "\ndry-run complete.\n" : "\npublished. Try: npx innerwarden --version\n");
