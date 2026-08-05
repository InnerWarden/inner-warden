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
import { verifyDownloadedFile } from "./verify-release-asset.mjs";

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
  // Verify BEFORE the bytes are packaged and before provenance is attached to
  // them (audit CI-02 / SUP-05). Fails closed for ALL six targets, not just the
  // host-native one: a `--version` smoke test catches a stale build, never a
  // swapped one.
  verifyDownloadedFile(dest, RELEASE, t.asset);
  process.stdout.write(`  verified ${t.asset} (sha256 + Ed25519)\n`);
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

// The wrapper must depend on the platform packages THIS run produced.
//
// These pins were hand-maintained and drifted: the wrapper shipped as 1.0.5 while
// still asking for `@innerwarden/cli-*@1.0.3`, so `npm i -g innerwarden` on a clean
// host resolved 1.0.5 and installed the 1.0.3 binary. Two releases of guard fixes
// were published, the registry's dist-tag moved both times, and no customer received
// either. Derived from VERSION here so the pin cannot disagree with what was built.
const pinned = Object.fromEntries(
  TARGETS.map((t) => [`@innerwarden/cli-${t.slug}`, VERSION]),
);
const mainPath = join(ROOT, "package.json");
const main = JSON.parse(readFileSync(mainPath, "utf8"));
const drifted = Object.entries(pinned).filter(
  ([name, v]) => main.optionalDependencies?.[name] !== v,
);
if (drifted.length) {
  main.optionalDependencies = pinned;
  writeFileSync(mainPath, JSON.stringify(main, null, 2) + "\n");
  process.stdout.write(
    `repinned ${drifted.length} optionalDependencies to ${VERSION}\n`,
  );
}

// Verify the BINARY, not just the version field.
//
// Platform packages are filled from the rolling `iw-guard` release, so the bytes are
// whatever that tag pointed at when this ran — publishing an npm version does not
// rebuild them. Package 1.0.5 shipped the 1.0.4 binary for exactly this reason: the
// guard release was never re-cut, and nothing checked. Only the host-native target
// can be executed here, which is enough to catch a stale rolling release.
const native = TARGETS.find(
  (t) => t.os === process.platform && t.cpu === process.arch,
);
if (native) {
  const bin = join(OUT, `cli-${native.slug}`, "bin", native.exe);
  const reported = execFileSync(bin, ["--version"], { encoding: "utf8" }).trim();
  if (!reported.endsWith(VERSION)) {
    process.stderr.write(
      `\nFATAL: packaging v${VERSION} but the downloaded binary reports "${reported}".\n` +
        `The rolling ${RELEASE.split("/").pop()} release has not been re-cut for this ` +
        `version, so publishing would ship stale bytes under a new version number.\n` +
        `Cut the guard release first, then re-run.\n`,
    );
    process.exit(1);
  }
  process.stdout.write(`verified ${native.slug} binary reports ${reported}\n`);
} else {
  process.stdout.write(
    `WARNING: no native target for ${process.platform}-${process.arch}; ` +
      `binary version left unverified\n`,
  );
}

process.stdout.write(`\nbuilt ${TARGETS.length} platform packages in ${OUT} (v${VERSION})\n`);
process.stdout.write("next: node scripts/publish.mjs   (after `npm login`)\n");
