#!/usr/bin/env node
// No known advisory in the npm tree, except the ones written down here.
//
// `npm audit` has no way to waive one advisory, so a single advisory with no
// way out would hold every pull request red, and the only escape would be to
// stop auditing. This runs `npm audit --json` and fails on every advisory at
// moderate or above, the way the plain command did, unless it is in WAIVERS
// below with a reason, the way `deny.toml` waives a crate.
//
// A waiver is narrow. It matches the advisory ID AND the package it names; the
// installed copies must all be at or below the last affected release; and the
// package must be a development dependency only (absent from
// `npm ls --omit=dev`), so nothing waived here ships in the bundle.
//
// A waiver is not forever. It fails once the registry publishes a release past
// the last affected one, and once the advisory no longer shows in the tree, so
// a stale entry cannot stay behind.
//
// Anything this script cannot read (output that is not JSON, an npm error, a
// report without the fields below, a registry that does not answer) fails:
// a check that could not run is never a pass.
//
//   node scripts/npm-audit.mjs

import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Advisories this tree carries knowingly. Each needs: the package, the last
 * release the advisory covers, and why it is accepted.
 */
export const WAIVERS = {
  // picomatch ReDoS through single-branch repeated extglobs. GitHub withdrew
  // this advisory on 2026-11-18, but the npm registry still serves it, so
  // `npm audit` still lists every picomatch release through 4.0.7, the latest
  // published, with no upgrade to take. picomatch only runs in the build and
  // test tools here (vite, vitest, tinyglobby, fdir), on globs this repo
  // writes. This entry goes when `npm audit` stops listing it: the stale
  // check below then fails until it is removed.
  "GHSA-fc5q-39xc-vjpf": { package: "picomatch", lastAffected: "4.0.7" },
};

const SEVERITY = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

/** The advisory ID at the end of a GitHub advisory URL. */
export function advisoryId(url) {
  const match = /GHSA(-[0-9a-z]{4}){3}$/i.exec(url ?? "");
  return match ? match[0] : String(url);
}

/** -1, 0 or 1 for two plain `x.y.z` versions; NaN when either is not one. */
export function compareVersions(a, b) {
  const parse = (v) => {
    const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(String(v));
    return m ? m.slice(1).map(Number) : null;
  };
  const [x, y] = [parse(a), parse(b)];
  if (!x || !y) return NaN;
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  }
  return 0;
}

/** Every version of `name` anywhere in an `npm ls --json --all` tree. */
export function versionsIn(tree, name) {
  const found = [];
  const walk = (node) => {
    for (const [dep, child] of Object.entries(node?.dependencies ?? {})) {
      if (dep === name && child?.version) found.push(child.version);
      walk(child);
    }
  };
  walk(tree);
  return found;
}

/** Whether an `npm audit --json` report has the shape this script reads. */
export function wellFormed(report) {
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  return (
    isObject(report) &&
    isObject(report.vulnerabilities) &&
    isObject(report.metadata) &&
    isObject(report.metadata.vulnerabilities) &&
    Object.values(report.vulnerabilities).every((v) => isObject(v) && Array.isArray(v.via))
  );
}

/**
 * Judge a well-formed `npm audit --json` report. Returns the advisories that
 * fail and the waived IDs that no longer appear. Only advisory objects count:
 * a package listed because it depends on a vulnerable one carries no advisory
 * of its own, and the advisory it inherits is judged where it is raised.
 *
 * `waived(id, name)` says whether the waiver for `id` applies to the
 * advisory as raised against package `name`.
 */
export function judge(report, waivers, minSeverity = "moderate", waived = () => true) {
  const seen = new Set();
  const failing = [];
  for (const vuln of Object.values(report.vulnerabilities)) {
    for (const via of vuln.via) {
      if (typeof via === "string") continue;
      const id = advisoryId(via.url);
      seen.add(id);
      if ((SEVERITY[via.severity] ?? 4) < SEVERITY[minSeverity]) continue;
      if (Object.hasOwn(waivers, id) && waivers[id].package === via.name && waived(id, via.name)) {
        continue;
      }
      failing.push({ id, package: via.name, severity: via.severity, title: via.title });
    }
  }
  const stale = Object.keys(waivers).filter((id) => !seen.has(id));
  return { failing, stale };
}

/** Run npm and return stdout, also when npm exits non-zero (audit does on a finding). */
function npm(args) {
  try {
    return execFileSync("npm", args, { cwd: webRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    if (typeof err.stdout === "string" && err.stdout.trim()) return err.stdout;
    throw new Error(`npm ${args.join(" ")} failed: ${err.message}`);
  }
}

const realNpm = {
  audit: () => npm(["audit", "--json"]),
  tree: (name, omitDev) => npm(["ls", name, "--all", "--json", ...(omitDev ? ["--omit=dev"] : [])]),
  latest: (name) => npm(["view", name, "version"]).trim(),
};

/**
 * The whole check. Returns the exit code; writes through `out` and `err`.
 * `io` is the npm it asks, injectable so every way it can fail is tested.
 */
export function main(io = realNpm, out = console.log, err = console.error, waivers = WAIVERS) {
  let report;
  try {
    report = JSON.parse(io.audit());
  } catch (e) {
    err(`npm audit could not be read: ${e.message}`);
    return 1;
  }
  if (report?.error) {
    err(`npm audit failed: ${JSON.stringify(report.error)}`);
    return 1;
  }
  if (!wellFormed(report)) {
    err("npm audit returned a report without vulnerabilities and metadata.vulnerabilities: refusing to call it clean");
    return 1;
  }

  const problems = [];
  const waived = (id, name) => {
    const w = waivers[id];
    try {
      const installed = versionsIn(JSON.parse(io.tree(name, false)), name);
      const shipped = versionsIn(JSON.parse(io.tree(name, true)), name);
      if (installed.length === 0) {
        problems.push(`waiver ${id}: ${name} is not in the installed tree`);
        return false;
      }
      const newer = installed.filter((v) => !(compareVersions(v, w.lastAffected) <= 0));
      if (newer.length > 0) {
        problems.push(`waiver ${id}: ${name} ${newer.join(", ")} is past the last affected ${w.lastAffected}`);
        return false;
      }
      if (shipped.length > 0) {
        problems.push(`waiver ${id}: ${name} is a runtime dependency (${shipped.join(", ")}), not only a dev one`);
        return false;
      }
      return true;
    } catch (e) {
      problems.push(`waiver ${id}: the installed tree could not be read: ${e.message}`);
      return false;
    }
  };

  const { failing, stale } = judge(report, waivers, "moderate", waived);
  for (const p of problems) err(p);
  for (const f of failing) err(`advisory ${f.id} (${f.severity}) in ${f.package}: ${f.title}`);
  for (const id of stale) {
    err(`waiver ${id} no longer matches anything in the tree: remove it from scripts/npm-audit.mjs`);
  }
  let ok = failing.length === 0 && stale.length === 0;
  for (const [id, w] of Object.entries(waivers)) {
    let latest;
    try {
      latest = io.latest(w.package);
    } catch (e) {
      err(`waiver ${id}: the registry did not say the latest ${w.package}: ${e.message}`);
      ok = false;
      continue;
    }
    if (latest !== w.lastAffected) {
      err(
        `waiver ${id}: ${w.package} ${latest} is published after the last affected ${w.lastAffected}: upgrade and drop the waiver if it is fixed`,
      );
      ok = false;
    }
  }
  if (!ok) return 1;
  out(`npm audit: no unwaived advisory at moderate or above (${Object.keys(waivers).length} waived)`);
  return 0;
}

/**
 * Whether this file is the one node was asked to run. Compared after
 * resolving links on both sides: a plain comparison was false when the script
 * was reached through a symlink, `main()` never ran, and the check exited 0
 * having audited nothing. Windows compares without case (drive letters).
 */
export function isEntry(argv1, self = fileURLToPath(import.meta.url), platform = process.platform) {
  return entryState(argv1, self, platform) === "entry";
}

/**
 * "entry" when node was asked to run this file, "other" when it was asked to
 * run another one (a test importing it), and "unresolved" when a path could
 * not be resolved and `argv1` names this file. That last one used to read as
 * "other": the gate exited 0 having audited nothing. It is a failure.
 */
export function entryState(argv1, self = fileURLToPath(import.meta.url), platform = process.platform) {
  if (!argv1) return "other";
  const same = (x, y) => (platform === "win32" ? x.toLowerCase() === y.toLowerCase() : x === y);
  try {
    const a = realpathSync(resolve(argv1));
    const b = realpathSync(self);
    return same(a, b) ? "entry" : "other";
  } catch {
    return same(basename(argv1), basename(self)) ? "unresolved" : "other";
  }
}

const state = entryState(process.argv[1]);
if (state === "unresolved") {
  console.error("npm audit: could not resolve the path this script was run from; nothing was audited");
  process.exit(1);
}
if (state === "entry") process.exit(main());
