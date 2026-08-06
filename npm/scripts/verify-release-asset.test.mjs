// Tests for the packaging-time release verifier (audit CI-02 / SUP-05).
//
// Run: node npm/scripts/verify-release-asset.test.mjs
// With real bytes: IW_REAL_ASSET_DIR=<dir> IW_REAL_ASSET=<name> node ...
//
// Uses a throwaway key for the synthetic cases so the tests never depend on the
// production key, and the real-artifact case (opt-in) proves the production key
// and the digest-signing assumption against bytes the project actually shipped.

import { generateKeyPairSync, createHash, sign as cryptoSign } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import assert from "node:assert/strict";

import {
  parseDigestSidecar,
  pemFromRawKey,
  verifyAsset,
  RELEASE_PUBLIC_KEY_B64,
} from "./verify-release-asset.mjs";

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`  ok    ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL  ${name}\n        ${e.message}`);
  }
}

/** A key pair plus a helper that signs the way the release does: over the digest. */
function throwawaySigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    pubB64: raw.toString("base64"),
    signed(bytes) {
      const digest = createHash("sha256").update(bytes).digest();
      return {
        sha: `${digest.toString("hex")}  some-asset`,
        sig: cryptoSign(null, digest, privateKey).toString("base64"),
      };
    },
  };
}

console.log("verify-release-asset");

test("a genuine artifact verifies", () => {
  const s = throwawaySigner();
  const bytes = Buffer.from("the real binary");
  const { sha, sig } = s.signed(bytes);
  verifyAsset(bytes, sha, sig, "asset", s.pubB64);
});

test("a tampered artifact is refused", () => {
  const s = throwawaySigner();
  const { sha, sig } = s.signed(Buffer.from("the real binary"));
  assert.throws(
    () => verifyAsset(Buffer.from("a swapped binary"), sha, sig, "asset"),
    /SHA-256 mismatch/,
  );
});

test("an artifact signed by another key is refused", () => {
  const ours = throwawaySigner();
  const theirs = throwawaySigner();
  const bytes = Buffer.from("attacker payload");
  const { sha, sig } = theirs.signed(bytes);
  assert.throws(
    () => verifyAsset(bytes, sha, sig, "asset", ours.pubB64),
    /signature is not valid/,
  );
});

test("malformed sidecars fail closed", () => {
  const s = throwawaySigner();
  const bytes = Buffer.from("x");
  const { sha, sig } = s.signed(bytes);
  assert.throws(() => verifyAsset(bytes, "", sig, "a", s.pubB64), /malformed .sha256/);
  assert.throws(() => verifyAsset(bytes, "deadbeef", sig, "a", s.pubB64), /malformed .sha256/);
  assert.throws(() => verifyAsset(bytes, sha, "c2hvcnQ=", "a", s.pubB64), /malformed .sig/);
});

test("the sidecar format the release writes is accepted", () => {
  const hex = "a".repeat(64);
  assert.equal(parseDigestSidecar(hex), hex);
  assert.equal(parseDigestSidecar(`${hex}  innerwarden-linux-x86_64`), hex);
  assert.equal(parseDigestSidecar("   "), null);
  assert.equal(parseDigestSidecar(hex.slice(0, 40)), null, "a truncated digest is not a prefix match");
});

test("the vendored production key is a usable Ed25519 key", () => {
  const pem = pemFromRawKey(RELEASE_PUBLIC_KEY_B64);
  assert.match(pem, /BEGIN PUBLIC KEY/);
  assert.equal(Buffer.from(RELEASE_PUBLIC_KEY_B64, "base64").length, 32);
});

// Opt-in: proves the production key and the digest-signing assumption against
// bytes the project actually published.
const realDir = process.env.IW_REAL_ASSET_DIR;
const realName = process.env.IW_REAL_ASSET;
if (realDir && realName && existsSync(`${realDir}/${realName}`)) {
  test(`a REAL published artifact verifies (${realName})`, () => {
    const bytes = readFileSync(`${realDir}/${realName}`);
    const sha = readFileSync(`${realDir}/${realName}.sha256`, "utf8");
    const sig = readFileSync(`${realDir}/${realName}.sig`, "utf8");
    verifyAsset(bytes, sha, sig, realName);
  });
  test(`a REAL artifact with one byte flipped is refused (${realName})`, () => {
    const bytes = readFileSync(`${realDir}/${realName}`);
    const sha = readFileSync(`${realDir}/${realName}.sha256`, "utf8");
    const sig = readFileSync(`${realDir}/${realName}.sig`, "utf8");
    bytes[bytes.length - 1] ^= 0xff;
    assert.throws(() => verifyAsset(bytes, sha, sig, realName), /SHA-256 mismatch/);
  });
} else {
  console.log("  skip  real-artifact cases (set IW_REAL_ASSET_DIR and IW_REAL_ASSET)");
}

console.log(failures === 0 ? "\nall passed" : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
