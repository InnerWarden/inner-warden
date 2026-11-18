#!/usr/bin/env node
// No known advisory in the npm tree, except the ones written down here.
//
// `npm audit` has no way to waive one advisory, so a single advisory with no
// patched release would hold every pull request red, and the only way out
// would be to stop auditing. This runs `npm audit --json` and fails on every
// advisory at moderate or above, the way the plain command did, unless its ID
// is in WAIVERS below with a reason, the way `deny.toml` waives a crate.
//
// A waiver is not forever. It names the last affected release of the package;
// once the registry has a newer one, this fails and asks for the upgrade and
// for the entry to go. It also fails when a waived advisory no longer shows in
// the tree, so a stale entry cannot stay behind.
//
//   node scripts/npm-audit.mjs

import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Advisories this tree carries knowingly. Each needs: the package, the last
 * release the advisory covers, why it is accepted, and where the fix is tracked.
 */
export const WAIVERS = {
  // picomatch ReDoS through single-branch repeated extglobs (high). The
  // advisory covers every release through 4.0.7, the latest published, so
  // there is no upgrade to take; vite and vitest, newest majors included,
  // require picomatch ^4.0.7. Here picomatch only runs in the build and test
  // tools (vite, vitest, tinyglobby, fdir) on glob patterns this repo writes;
  // nothing in the shipped bundle or the binary uses it, and no outside input
  // reaches it as a glob. Take the patched release when it ships and drop this
  // entry (BI NEW-20261118-picomatch-redos-no-fix).
  "GHSA-fc5q-39xc-vjpf": { package: "picomatch", lastAffected: "4.0.7" },
};

const SEVERITY = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

/** The advisory ID at the end of a GitHub advisory URL. */
export function advisoryId(url) {
  const match = /GHSA(-[0-9a-z]{4}){3}$/i.exec(url ?? "");
  return match ? match[0] : String(url);
}

/**
 * Judge an `npm audit --json` report. Returns the advisories that fail the
 * check and the waived IDs that no longer appear. Only advisory objects count:
 * a package listed because it depends on a vulnerable one carries no advisory
 * of its own, and the advisory it inherits is judged where it is raised.
 */
export function judge(report, waivers, minSeverity = "moderate") {
  const seen = new Set();
  const failing = [];
  for (const vuln of Object.values(report.vulnerabilities ?? {})) {
    for (const via of vuln.via ?? []) {
      if (typeof via === "string") continue;
      const id = advisoryId(via.url);
      seen.add(id);
      if ((SEVERITY[via.severity] ?? 4) < SEVERITY[minSeverity]) continue;
      if (Object.hasOwn(waivers, id)) continue;
      failing.push({ id, package: via.name, severity: via.severity, title: via.title });
    }
  }
  const stale = Object.keys(waivers).filter((id) => !seen.has(id));
  return { failing, stale };
}

function main() {
  let raw;
  try {
    raw = execFileSync("npm", ["audit", "--json"], { cwd: webRoot, encoding: "utf8" });
  } catch (err) {
    // npm audit exits non-zero when it finds anything; the JSON is still on stdout.
    raw = err.stdout;
  }
  const report = JSON.parse(raw);
  if (report.error) {
    console.error(`npm audit failed: ${JSON.stringify(report.error)}`);
    process.exit(1);
  }

  const { failing, stale } = judge(report, WAIVERS);
  let ok = true;
  for (const f of failing) {
    console.error(`advisory ${f.id} (${f.severity}) in ${f.package}: ${f.title}`);
    ok = false;
  }
  for (const id of stale) {
    console.error(`waiver ${id} no longer matches anything in the tree: remove it from scripts/npm-audit.mjs`);
    ok = false;
  }
  for (const [id, w] of Object.entries(WAIVERS)) {
    const latest = execFileSync("npm", ["view", w.package, "version"], { cwd: webRoot, encoding: "utf8" }).trim();
    if (latest !== w.lastAffected) {
      console.error(
        `waiver ${id}: ${w.package} ${latest} is published after the last affected ${w.lastAffected}: upgrade and drop the waiver if it is fixed`,
      );
      ok = false;
    }
  }
  if (!ok) process.exit(1);
  console.log(`npm audit: no unwaived advisory at moderate or above (${Object.keys(WAIVERS).length} waived)`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
