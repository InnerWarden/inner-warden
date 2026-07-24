#!/usr/bin/env node
// Assemble the per-platform npm packages by downloading the signed prebuilt
// binaries from the innerwarden-releases GitHub release and dropping each into
// its own @innerwarden/cli-<platform>-<arch> package under npm/platforms/.
//
// Usage:  node scripts/build.mjs [version]
// Default version is read from the main package.json.

import { mkdirSync, writeFileSync, chmodSync, rmSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const MAIN_PKG = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const VERSION = process.argv[2] || MAIN_PKG.version;
const OUT = join(ROOT, "platforms");
const RELEASE = "https://github.com/InnerWarden/innerwarden-releases/releases/download/iw-guard";

// npm process.platform / process.arch -> release asset name.
const TARGETS = [
  { slug: "linux-x64", os: "linux", cpu: "x64", asset: "innerwarden-linux-x86_64", exe: "innerwarden" },
  { slug: "linux-arm64", os: "linux", cpu: "arm64", asset: "innerwarden-linux-aarch64", exe: "innerwarden" },
  { slug: "darwin-x64", os: "darwin", cpu: "x64", asset: "innerwarden-macos-x86_64", exe: "innerwarden" },
  { slug: "darwin-arm64", os: "darwin", cpu: "arm64", asset: "innerwarden-macos-aarch64", exe: "innerwarden" },
  { slug: "win32-x64", os: "win32", cpu: "x64", asset: "innerwarden-windows-x86_64.exe", exe: "innerwarden.exe" },
  { slug: "win32-arm64", os: "win32", cpu: "arm64", asset: "innerwarden-windows-aarch64.exe", exe: "innerwarden.exe" },
];

rmSync(OUT, { recursive: true, force: true });

for (const t of TARGETS) {
  const pkgDir = join(OUT, `cli-${t.slug}`);
  const binDir = join(pkgDir, "bin");
  mkdirSync(binDir, { recursive: true });

  const dest = join(binDir, t.exe);
  process.stdout.write(`downloading ${t.asset} -> @innerwarden/cli-${t.slug}\n`);
  execFileSync("curl", ["-fsSL", "-o", dest, `${RELEASE}/${t.asset}`], { stdio: "inherit" });
  chmodSync(dest, 0o755);

  const pkg = {
    name: `@innerwarden/cli-${t.slug}`,
    version: VERSION,
    description: `InnerWarden Community prebuilt binary for ${t.os}-${t.cpu}.`,
    os: [t.os],
    cpu: [t.cpu],
    files: ["bin"],
    license: "Apache-2.0",
    homepage: "https://innerwarden.com",
    repository: {
      type: "git",
      url: "git+https://github.com/InnerWarden/inner-warden.git",
      directory: "npm",
    },
  };
  writeFileSync(join(pkgDir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
}

process.stdout.write(`\nbuilt ${TARGETS.length} platform packages in ${OUT} (v${VERSION})\n`);
process.stdout.write("next: node scripts/publish.mjs   (after `npm login`)\n");
