#!/usr/bin/env node
"use strict";

// The npm launcher had no tests, and the thing it says when it cannot find its
// binary is the first sentence a large share of users ever read from this
// product. It was wrong in the case that happens most.
//
// Run: node npm/test/shim-message.test.js

const assert = require("assert");
const {
  binaryMissingMessage,
  SUPPORTED_PLATFORMS,
  SUPPORTED_ARCHES,
} = require("../bin/innerwarden.js");

let pass = 0;
function it(name, fn) {
  try {
    fn();
    pass += 1;
    console.log(`  ok  ${name}`);
  } catch (err) {
    console.error(`  FAIL  ${name}`);
    console.error(`        ${err.message}`);
    process.exitCode = 1;
  }
}

// THE regression. Found on a real host: `innerwarden uninstall` removes the
// platform binary and leaves this launcher on PATH. The launcher then said
//
//   no prebuilt binary for linux-x64.
//   Supported platforms: linux, darwin, win32 on x64 and arm64.
//
// naming the running platform as unsupported one line after listing it as
// supported. A reader concludes the product does not run on their machine; the
// cause is that a file was deleted.
//
// FAILS ON REVERT: return the single old message for both branches.
it("a supported platform is told its binary is MISSING, not unsupported", () => {
  for (const [platform, arch] of [
    ["linux", "x64"],
    ["linux", "arm64"],
    ["darwin", "arm64"],
    ["win32", "x64"],
  ]) {
    const msg = binaryMissingMessage(platform, arch);
    assert.ok(
      msg.includes("IS supported"),
      `${platform}-${arch} is a published target and must not be reported as unsupported:\n${msg}`
    );
    assert.ok(
      !msg.includes("no prebuilt binary"),
      `${platform}-${arch} must not be told there is no build for it:\n${msg}`
    );
    assert.ok(
      msg.includes("Reinstall:"),
      `the message must carry the command that fixes it:\n${msg}`
    );
  }
});

// THE SECOND REGRESSION, and the reason the assertion above changed shape.
//
// The old test asserted `msg.includes("npm install -g innerwarden")`. That
// string is a SUBSTRING of the very command being handed out, so it passed
// before the fix and would have passed after it, whichever way the message went.
// A test that cannot fail is not a gate, and this one was actively holding the
// defect in place: it pinned the remedy that does not work.
//
// `npm install -g` writes to npm's global prefix. On a distro-packaged Node
// that prefix is /usr/local/lib/node_modules and it is root-owned, so on Linux
// the command exits EACCES. Measured on a clean Ubuntu 26.04 machine. This
// message is read at the moment the reader has nothing working, which is the
// worst possible moment to spend on a second failure.
//
// FAILS ON REVERT: put the npm command back on the `Reinstall:` line and the
// ordering assertion flips.
it("the remedy that needs no root is the one offered first", () => {
  for (const [platform, arch, expected] of [
    ["linux", "x64", "curl -fsSL https://innerwarden.com/free | sh"],
    ["linux", "arm64", "curl -fsSL https://innerwarden.com/free | sh"],
    ["darwin", "arm64", "curl -fsSL https://innerwarden.com/free | sh"],
    ["win32", "x64", "irm https://innerwarden.com/free.ps1 | iex"],
  ]) {
    const msg = binaryMissingMessage(platform, arch);
    assert.ok(
      msg.includes(expected),
      `${platform}-${arch} must be offered the rootless installer for its OS:\n${msg}`
    );
    const rootlessAt = msg.indexOf(expected);
    const npmAt = msg.indexOf("npm install -g innerwarden");
    assert.ok(
      npmAt === -1 || rootlessAt < npmAt,
      `the command that works must come before the one that needs root:\n${msg}`
    );
  }
});

// npm is not banned: it carries provenance and it is the right choice for
// someone who already manages their tools with npm. It just cannot be offered
// without saying what it needs, to a reader who is already stuck.
it("npm is still offered, and never without the sudo caveat", () => {
  const msg = binaryMissingMessage("linux", "x64");
  assert.ok(msg.includes("npm install -g innerwarden"), msg);
  assert.ok(
    /sudo/i.test(msg),
    `offering npm on Linux without naming sudo repeats the defect:\n${msg}`
  );
});

// A Windows reader must not be handed a shell pipeline that does not exist on
// their machine, and a Unix reader must not be handed PowerShell.
it("each platform is offered its own installer and not the other one", () => {
  const win = binaryMissingMessage("win32", "arm64");
  assert.ok(!win.includes("curl -fsSL"), `Windows got a curl pipeline:\n${win}`);
  const nix = binaryMissingMessage("linux", "x64");
  assert.ok(!nix.includes("irm "), `Linux got PowerShell:\n${nix}`);
});

it("an unsupported platform is still told plainly that there is no build", () => {
  const msg = binaryMissingMessage("aix", "ppc64");
  assert.ok(msg.includes("no prebuilt binary for aix-ppc64"), msg);
  assert.ok(!msg.includes("IS supported"), msg);
  assert.ok(msg.includes("issues"), "it must say where to ask for the platform");
});

// A supported ARCH on an unsupported PLATFORM, and the reverse. Both halves have
// to match or the message is wrong for one of them, which is exactly how the
// original went wrong.
it("both halves have to match before it claims support", () => {
  assert.ok(binaryMissingMessage("aix", "x64").includes("no prebuilt binary"));
  assert.ok(binaryMissingMessage("linux", "s390x").includes("no prebuilt binary"));
});

// The lists are printed to the user, so a set that drifts from what the message
// claims is the defect this file exists to stop, one level up.
it("the advertised set is the set the message is built from", () => {
  const msg = binaryMissingMessage("aix", "ppc64");
  for (const p of SUPPORTED_PLATFORMS) {
    assert.ok(msg.includes(p), `the message must list ${p}`);
  }
  for (const a of SUPPORTED_ARCHES) {
    assert.ok(msg.includes(a), `the message must list ${a}`);
  }
});

// Requiring the launcher must not run it. If this regressed, every test run
// would try to spawn the real binary and the file could not be tested at all.
it("requiring the launcher does not execute it", () => {
  assert.strictEqual(typeof binaryMissingMessage, "function");
});

console.log(`\nshim-message: ${pass} passed${process.exitCode ? ", FAILURES above" : ", 0 failed"}`);
