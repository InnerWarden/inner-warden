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

// The platform sets this package actually publishes a binary for. Kept beside
// the message so the two cannot disagree: the previous message listed these as
// supported in the line AFTER telling the user their platform had no binary,
// which is only true for one of the two ways this can fail.
const SUPPORTED_PLATFORMS = ["linux", "darwin", "win32"];
const SUPPORTED_ARCHES = ["x64", "arm64"];

// Pure, and exported, because it is the whole decision and the runtime path
// around it cannot be exercised on a machine that HAS the binary.
function binaryMissingMessage(platform, arch) {
  const here = `${platform}-${arch}`;
  const isSupported =
    SUPPORTED_PLATFORMS.includes(platform) && SUPPORTED_ARCHES.includes(arch);

  if (isSupported) {
    // The common case, and the one the old message described as the opposite of
    // what it is. Seen on a real machine: `innerwarden uninstall` removes the
    // platform binary and leaves this shim on PATH, and the shim then reported
    // linux-x64 as having no build while listing linux and x64 as supported.
    // The reader concludes the product does not run on their machine.
    // The remedy is read at the exact moment the reader has nothing working, so
    // it must be a command that RUNS. `npm install -g` writes to npm's global
    // prefix; on a distro-packaged Node that prefix is /usr/local/lib/node_modules
    // and root-owned, so on Linux it exits EACCES. Measured on a clean Ubuntu
    // 26.04 machine. Handing that to someone whose install is already broken
    // spends their next attempt on a second failure.
    //
    // The shell installer needs no root on any platform: it verifies the signed
    // binary and installs into the user's own ~/.local/bin.
    const rootless =
      platform === "win32"
        ? `  irm https://innerwarden.com/free.ps1 | iex\n`
        : `  curl -fsSL https://innerwarden.com/free | sh\n`;
    return (
      `InnerWarden: ${here} IS supported, but its binary is not installed.\n` +
      `The launcher is here and the program it launches is missing, which\n` +
      `usually means one of:\n` +
      `  * 'innerwarden uninstall' removed it and left this launcher behind;\n` +
      `  * the install ran with --ignore-scripts or --no-optional;\n` +
      `  * the platform package failed to download.\n` +
      `Reinstall:\n` +
      rootless +
      `Or through npm, which on Linux needs sudo because its global prefix is\n` +
      `root-owned there:\n` +
      `  npm uninstall -g innerwarden && npm install -g innerwarden\n`
    );
  }
  return (
    `InnerWarden: no prebuilt binary for ${here}.\n` +
    `Supported: ${SUPPORTED_PLATFORMS.join(", ")} on ${SUPPORTED_ARCHES.join(" and ")}.\n` +
    `If your platform should be supported, please open an issue:\n` +
    `  https://github.com/InnerWarden/inner-warden/issues\n`
  );
}

module.exports = { binaryMissingMessage, SUPPORTED_PLATFORMS, SUPPORTED_ARCHES };

// Required as a module by the test; run as a script by every user.
if (require.main !== module) {
  return;
}

const binary = resolveBinary();
if (!binary) {
  process.stderr.write(binaryMissingMessage(process.platform, process.arch));
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
