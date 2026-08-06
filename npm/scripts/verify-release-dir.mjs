// Verify already-downloaded release assets in a directory (audit CI-02 / SUP-05).
//
// Used by the .deb/.rpm workflow, which downloads the binaries and their
// sidecars itself. Exits non-zero on the first failure so packaging never
// proceeds with bytes that were not proven to be the published ones.

import { readFileSync } from "node:fs";
import { verifyAsset } from "./verify-release-asset.mjs";

const [dir, ...assets] = process.argv.slice(2);
if (!dir || assets.length === 0) {
  console.error("usage: verify-release-dir.mjs <dir> <asset> [asset...]");
  process.exit(2);
}

for (const asset of assets) {
  try {
    verifyAsset(
      readFileSync(`${dir}/${asset}`),
      readFileSync(`${dir}/${asset}.sha256`, "utf8"),
      readFileSync(`${dir}/${asset}.sig`, "utf8"),
      asset,
    );
    console.log(`verified ${asset} (sha256 + Ed25519)`);
  } catch (e) {
    console.error(`REFUSING to package: ${e.message}`);
    process.exit(1);
  }
}
