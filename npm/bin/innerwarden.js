#!/usr/bin/env node
"use strict";

// Resolve the platform-specific prebuilt binary (shipped inside the matching
// @innerwarden/cli-<platform>-<arch> optional dependency) and hand off to it.
//
// There is deliberately no postinstall step and no network download: the
// binaries live inside the per-platform npm packages, so `npm install
// --ignore-scripts` works and nothing is fetched at install time. This is the
// esbuild/biome distribution model and keeps a security tool auditable.

const { spawnSync } = require("child_process");

function resolveBinary() {
  const { platform, arch } = process;
  const pkg = `@innerwarden/cli-${platform}-${arch}`;
  const exe = platform === "win32" ? "innerwarden.exe" : "innerwarden";
  try {
    return require.resolve(`${pkg}/bin/${exe}`);
  } catch (_err) {
    return null;
  }
}

const binary = resolveBinary();
if (!binary) {
  process.stderr.write(
    `InnerWarden: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      `Supported platforms: linux, darwin, win32 on x64 and arm64.\n` +
      `If your platform should be supported, please open an issue:\n` +
      `  https://github.com/InnerWarden/inner-warden/issues\n`
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  process.stderr.write(`InnerWarden: failed to launch ${binary}: ${result.error.message}\n`);
  process.exit(1);
}
if (typeof result.status === "number") {
  process.exit(result.status);
}
// Terminated by signal.
process.exit(1);
