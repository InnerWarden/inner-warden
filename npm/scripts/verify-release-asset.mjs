// Verify a downloaded release asset before it is packaged (audit CI-02 / SUP-05).
//
// The repackagers used to curl each binary and package it with no check at all.
// Only the host-native target got a `--version` smoke test, which catches a
// stale build and not a swapped one; the other five got a warning. npm
// provenance was then attached to those unverified bytes, so the attestation
// said "npm built this" while saying nothing about WHAT was built.
//
// The project already publishes the two sidecars that answer that. This module
// uses them, and fails closed: a missing sidecar is an error, never a skip.
//
// The release signs the DIGEST, not the file:
//     openssl dgst -sha256 -binary <bin> > digest
//     openssl pkeyutl -sign -inkey key.pem -rawin -in digest | base64 -w0
// so the message to verify is the 32-byte sha256, not the artifact bytes.

import { execFileSync } from "node:child_process";
import { createHash, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";

// Raw 32-byte Ed25519 release public key, base64. The same key the installer
// pins and the CLI compiles in. Vendored HERE so packaging never has to trust
// something fetched at packaging time.
export const RELEASE_PUBLIC_KEY_B64 =
  process.env.IW_RELEASE_PUBKEY_B64 || "vR3bZQMGNQ7tfoKirl4mbBCE6DekmmEFADL5g984PC4=";

/** DER-wrap a raw Ed25519 public key so node's crypto can import it. */
export function pemFromRawKey(b64) {
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) throw new Error(`release public key must be 32 bytes, got ${raw.length}`);
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  const body = der.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
}

/**
 * Parse a `sha256sum`-style sidecar (`<hex>` or `<hex>  <name>`).
 * Anything that is not exactly 64 hex characters is rejected: a lenient parse
 * would let a truncated sidecar quietly weaken the check.
 */
export function parseDigestSidecar(raw) {
  const first = String(raw).trim().split(/\s+/)[0] || "";
  return /^[0-9a-fA-F]{64}$/.test(first) ? first.toLowerCase() : null;
}

/**
 * Throw unless `bytes` match both sidecars.
 *
 * `pubKeyB64` defaults to the vendored production pin. It is a parameter rather
 * than only a module constant so a test can verify against a throwaway key
 * without depending on the production one, and so a fork can pass its own.
 */
export function verifyAsset(bytes, shaSidecar, sigSidecar, label = "asset", pubKeyB64 = RELEASE_PUBLIC_KEY_B64) {
  const expected = parseDigestSidecar(shaSidecar);
  if (!expected) throw new Error(`${label}: malformed .sha256 sidecar`);

  const actual = createHash("sha256").update(bytes).digest();
  if (actual.toString("hex") !== expected) {
    throw new Error(`${label}: SHA-256 mismatch (published ${expected}, got ${actual.toString("hex")})`);
  }

  const sig = Buffer.from(String(sigSidecar).trim(), "base64");
  if (sig.length !== 64) throw new Error(`${label}: malformed .sig sidecar (${sig.length} bytes)`);

  // `null` algorithm: Ed25519 signs the message directly.
  const ok = cryptoVerify(null, actual, pemFromRawKey(pubKeyB64), sig);
  if (!ok) throw new Error(`${label}: signature is not valid for these bytes`);
}

/** Download a sidecar as text. Fails closed when it is absent. */
export function fetchSidecar(url, label) {
  try {
    return execFileSync("curl", ["-fsSL", url], { encoding: "utf8" });
  } catch {
    throw new Error(`${label}: sidecar missing at ${url}; refusing to package unverified bytes`);
  }
}

/** Verify an already-downloaded file against its published sidecars. */
export function verifyDownloadedFile(path, baseUrl, assetName) {
  const bytes = readFileSync(path);
  const sha = fetchSidecar(`${baseUrl}/${assetName}.sha256`, assetName);
  const sig = fetchSidecar(`${baseUrl}/${assetName}.sig`, assetName);
  verifyAsset(bytes, sha, sig, assetName);
}
