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
      msg.includes("npm install -g innerwarden"),
      `the message must carry the command that fixes it:\n${msg}`
    );
  }
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
