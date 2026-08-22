#!/usr/bin/env node
// Set the Community version in every place that has to agree.
//
// Cutting 1.3.5 by hand meant editing `Cargo.toml`, `npm/package.json`'s
// `version`, AND its six `optionalDependencies` pins. Missing the third is easy
// and it fails CI at "npm optionalDependencies match the package version",
// which is a good check and a slow way to find out.
//
// The pins are not decoration: `npm install -g innerwarden` resolves the
// platform package from them, so a wrapper at 1.3.5 pinning 1.3.4 installs the
// OLD binary under the NEW version number. That is the same class of drift the
// channel chaining fixed, one level down.
//
// Usage:  node npm/scripts/set-version.mjs 1.3.5
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error("usage: node npm/scripts/set-version.mjs <x.y.z>");
  process.exit(2);
}

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..", "..");
const pkgPath = join(repo, "npm", "package.json");
const cargoPath = join(repo, "Cargo.toml");

const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
const before = pkg.version;
pkg.version = version;
for (const name of Object.keys(pkg.optionalDependencies ?? {})) {
  pkg.optionalDependencies[name] = version;
}
writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);

// Only the workspace version line, which is the first `version = "..."` under
// [workspace.package]. A blunt global replace would rewrite dependency pins.
const cargo = readFileSync(cargoPath, "utf8");
let replaced = false;
const out = cargo
  .split("\n")
  .map((line) => {
    if (!replaced && /^version\s*=\s*"\d+\.\d+\.\d+/.test(line)) {
      replaced = true;
      return `version = "${version}"`;
    }
    return line;
  })
  .join("\n");
if (!replaced) {
  console.error("could not find the workspace version line in Cargo.toml");
  process.exit(1);
}
writeFileSync(cargoPath, out);

const pins = Object.keys(pkg.optionalDependencies ?? {}).length;
console.log(`${before} -> ${version}`);
console.log(`  npm/package.json version and ${pins} optionalDependencies pins`);
console.log(`  Cargo.toml workspace version`);
console.log(`Now run: cargo update -w`);
