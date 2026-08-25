# Distribution, install, and release runbook

The single source of truth for how the free Community CLI (`innerwarden`) is
packaged, published, signed, verified, and re-published on every new version.
If you are cutting a release or touching any install channel, read this first
and update it when the process changes.

User-facing install docs (the page we send people) live at
<https://innerwarden.com/docs/installation> (source:
`inner-warden-site` `client/src/content/docs/installation.md`). This file is the
**maintainer** side: how those artifacts are built and published.

---

## Where everything lives (the map)

| Artifact | Built from | Published to | Config in this repo |
| --- | --- | --- | --- |
| Signed binaries (`innerwarden-<os>-<arch>` + `.sha256` + `.sig`) | **this repo**, crate `cli`, via `.github/workflows/release-guard.yml` | rolling `iw-guard` release on `InnerWarden/innerwarden-releases` | `.github/workflows/release-guard.yml` |
| npm packages (7: `innerwarden` + 6 `@innerwarden/cli-<os>-<arch>`) | the binaries above | npmjs.com | `npm/` + `.github/workflows/npm-publish.yml` |
| `.deb` / `.rpm` (amd64 + arm64) | the binaries above, via nfpm | attached to the `iw-guard` release | `packaging/` + `.github/workflows/linux-packages.yml` |
| Shell installer (`curl \| sh`), PowerShell installer, Scoop manifest, public key | n/a (hand-maintained) | `innerwarden.com/free` | **`InnerWarden/innerwarden-releases`** (the distribution repo, not here) |
| In-place upgrade (`innerwarden upgrade`) | the binary already installed | n/a - reads the `iw-guard` release directly | `crates/cli/src/upgrade.rs`, `crates/cli/src/release_verify.rs` |

**Everything wraps the same signed binaries.** The binaries are the root of
trust; npm, deb, rpm, Scoop, ubi/eget/mise all fetch or embed them.

### Repo map (do not confuse these)

- **`InnerWarden/inner-warden`** (this repo): Community source. Builds, signs, and releases the free binary. All Community work goes here.
- **`InnerWarden/innerwarden-active-defence`**: the paid host stack (sensor, agent, exec-gate, eBPF).
- **`InnerWarden/innerwarden-releases`**: distribution. Holds the rolling `iw-guard` release, an immutable `guard-vX.Y.Z` release per cut, plus the installers, Scoop manifest, and `innerwarden-release.pub`.
- **`InnerWarden/innerwarden`** (the old monorepo): **retired for Community** as of 2026-07-24. Its `release-guard.yml` is now a stub that fails on purpose, and its `RELEASE_SIGNING_KEY` is the old, rotated-out key. Do not build or release Community there.

---

## Install methods (summary)

Full detail + copy-paste commands: <https://innerwarden.com/docs/installation>.

- **npm (all OSes):** `npm install -g innerwarden` / `npx innerwarden`. Prebuilt, signed provenance, no postinstall. Needs `sudo` on Linux: npm's global prefix is `/usr/local/lib/node_modules` on a distro-packaged Node and is root-owned, so without it the command exits EACCES before InnerWarden is reached.
- **Debian/Ubuntu:** `sudo apt install ./innerwarden_<v>_amd64.deb`
- **Fedora/RHEL/Rocky:** `sudo dnf install .../innerwarden-<v>-1.x86_64.rpm`
- **macOS/Linux shell:** `curl -fsSL https://innerwarden.com/free | sh`
- **Windows:** `irm https://innerwarden.com/free.ps1 | iex` or Scoop
- **ubi / eget / mise:** read the release directly
- **From source:** `cargo install --git https://github.com/InnerWarden/inner-warden innerwarden` (crates.io + `cargo binstall` are pending)

---

## npm

### Layout (esbuild / biome model)

- `npm/package.json` -> the main package `innerwarden`. A tiny Node shim
  (`npm/bin/innerwarden.js`) resolves the one platform package matching the
  user's OS/CPU (declared as `optionalDependencies`) and execs its binary.
- Six platform packages `@innerwarden/cli-{linux,darwin,win32}-{x64,arm64}`,
  each shipping one prebuilt binary. **No postinstall, no install-time
  download** (works with `npm install --ignore-scripts`).
- `npm/scripts/build.mjs` downloads the binaries from the `iw-guard` release,
  **verifies SHA-256 + Ed25519 for all six targets before packaging**, refuses to
  continue if the downloaded binary does not report the version being packaged,
  auto-repins `optionalDependencies` to that version, and assembles
  `npm/platforms/*` (gitignored).
- `npm/scripts/publish.mjs` publishes the platform packages first, then the main
  package. Idempotent (skips already-published versions), supports `NPM_OTP` and
  `NPM_PROVENANCE=1`.

### Publishing (OIDC, no token)

Publishing runs from CI via **GitHub OIDC trusted publishing** with a signed
provenance attestation. There is no long-lived npm token.

To publish a new version:

1. Bump `version` in `npm/package.json` **and** the six `optionalDependencies`
   versions to match (they are pinned exact).
2. **Wait for CI to be green on the exact commit**, then run the **Publish to npm
   (OIDC)** workflow (`npm-publish.yml`), or push a tag `npm-v<version>`. The
   workflow's `gate` job queries the checks API for that SHA and refuses unless
   every completed CI run concluded `success`; tagging before CI finishes fails
   the publish, it does not queue it. The `publish` job also runs in the
   `npm-publish` environment, so it waits for a reviewer once that environment is
   configured with one.
3. The workflow upgrades npm, assembles the platform packages, and publishes all
   seven with `--provenance`.

One-time setup (already done): a Trusted Publisher is configured on npmjs.com for
each of the seven packages, pointing at `InnerWarden/inner-warden` +
`npm-publish.yml`. npm has no org-level trusted publisher, so it is per-package.

### Manual publish (fallback)

`cd npm && node scripts/build.mjs && node scripts/publish.mjs`. This needs npm
2FA at publish time (see gotchas).

---

## Linux packages (.deb / .rpm)

- `packaging/nfpm.yaml` describes one binary at `/usr/bin/innerwarden`
  (metadata: Apache-2.0, homepage, maintainer). Uses `${PKG_ARCH}`,
  `${PKG_VERSION}`, `${PKG_BIN}` placeholders.
- `packaging/build-linux-packages.sh <version> <amd64-bin> <arm64-bin> [out]`
  resolves the template per architecture and emits `.deb` + `.rpm` for amd64 and
  arm64 via **nfpm** (no dpkg/rpmbuild toolchain).
- `.github/workflows/linux-packages.yml` rebuilds from the release binaries,
  **test-installs** the `.deb` on Ubuntu and the `.rpm` in a Rocky Linux
  container (`innerwarden --version`), and uploads the packages as artifacts.

### Publishing a new version

1. Run the **Linux packages** workflow (`linux-packages.yml`) AFTER the guard
   release has been cut for this version. The workflow asserts that the binary
   the rolling release currently serves reports the version being packaged, so
   running it early fails loudly instead of shipping a `.deb` labelled 1.1.0 that
   contains the previous binary.
2. Nothing to attach by hand: the workflow generates the `.sha256` sidecars and
   uploads the `.deb`/`.rpm` to the rolling `iw-guard` release itself, but only
   after both test-installs pass.
3. **Still manual:** deleting the PREVIOUS version's package assets. `--clobber`
   overwrites same-named files, and the package filenames carry the version, so
   the old ones linger until removed:
   `gh release delete-asset iw-guard <old-file> --repo InnerWarden/innerwarden-releases`.

Local one-off:
`packaging/build-linux-packages.sh 1.0.0 ./innerwarden-linux-x86_64 ./innerwarden-linux-aarch64 out`

---

## Signing and verification

- Every release binary ships `<asset>.sha256` (bare hash) and `<asset>.sig`
  (Ed25519 **over the SHA-256 digest** of the binary). The release publishes the
  public key as `innerwarden-release.pub` (PEM, `MCowBQYDK2VwAyEA...`).
- The `.deb`/`.rpm` ship a standard-format `<file>.sha256`.
- npm ships a signed **provenance** attestation (verify with
  `npm audit signatures`, or see it on the package page).
- **Key rotated 2026-07-24.** The previous private key was lost, so the signing
  key was rotated. The current public key (raw 32 bytes, base64) is
  `vR3bZQMGNQ7tfoKirl4mbBCE6DekmmEFADL5g984PC4=`, held as `RELEASE_SIGNING_KEY`
  in this repo and published as `innerwarden-release.pub`. Binaries signed with
  the old key no longer verify.

  **There are now three pin sites, not one.** A rotation must update all of them:

  1. `crates/cli/src/release_verify.rs` (`RELEASE_PUBLIC_KEY_B64`) - compiled
     into every shipped binary and used by `innerwarden upgrade`.
  2. `npm/scripts/verify-release-asset.mjs` (`RELEASE_PUBLIC_KEY_B64`) - used by
     the npm and `.deb`/`.rpm` packaging paths.
  3. `iw-guard-install.sh` in the distribution repo - the `curl | sh` pin.

  The first one has a consequence the others do not: an already-installed binary
  verifies its own upgrade with the key it was BUILT with, so a rotation
  permanently breaks `innerwarden upgrade` for the existing installed base. Those
  users have to reinstall from a channel that ships the new pin. Order a rotation
  as: land both source pins, cut the release, then merge the installer pin in the
  distribution repo. Between the last two steps the installer pins a key the
  published binaries were not signed with, so installs fail closed - correct, but
  keep the window short.

Verify a binary (needs OpenSSL >= 1.1.1; macOS: `brew install openssl@3`):

```sh
base=https://github.com/InnerWarden/innerwarden-releases/releases/download/iw-guard
asset=innerwarden-linux-x86_64
curl -fsSLO "$base/$asset"; curl -fsSLO "$base/$asset.sig"; curl -fsSLO "$base/innerwarden-release.pub"
openssl dgst -sha256 -binary "$asset" > digest.bin
base64 -d < "$asset.sig" > sig.bin        # macOS: base64 -D
openssl pkeyutl -verify -pubin -inkey innerwarden-release.pub -rawin -in digest.bin -sigfile sig.bin
#   -> Signature Verified Successfully
```

The `curl | sh` installer does this automatically against a public key **pinned
inside the installer**, so it rejects a swapped binary even from a compromised
release host.

---

## Cut-a-release checklist

When a new Community version ships:

0. **Version**: bump `version` under `[workspace.package]` in this repo's
   `Cargo.toml`, run `cargo update -w`, and bump `npm/package.json` (the main
   version **and** the six pinned `optionalDependencies`). The new version MUST
   be higher than what npm already serves, or the release silently regresses
   users. Merge that first.
1. **Binaries**: run **this repo's** `release-guard.yml` (`workflow_dispatch` or
   a `guard-v*` tag). It builds all six targets, signs them with
   `RELEASE_SIGNING_KEY`, stamps the pinned public key into the installer, and
   publishes the same signed bytes twice on `InnerWarden/innerwarden-releases`:
   once to the immutable `guard-vX.Y.Z` tag, once to the rolling `iw-guard` tag.
   The version comes from the built binary, not from the tag. Republishing an
   existing `guard-vX.Y.Z` is refused: bump the version instead.
### Pinning and rollback

The rolling `iw-guard` tag always carries the newest build, so its binaries are
replaced on every cut. The per-version tag is what makes an install
reproducible and a rollback possible:

```sh
# install an exact cut
IW_GUARD_TAG=guard-v1.3.7 curl -fsSL https://innerwarden.com/free | sh

# roll a host back to the last known-good one
IW_GUARD_TAG=guard-v1.3.6 curl -fsSL https://innerwarden.com/free | sh
```

Rolling back the DEFAULT install (what `https://innerwarden.com/free` serves
with no variable set) means re-running `release-guard.yml` from the older
commit, which republishes the rolling tag from those bytes. That is a pipeline
run, not an asset copy, because the rolling tag must keep matching a real cut.

2. **npm**: nothing to run. `npm-publish.yml` chains off a successful
   `release-guard.yml` through `workflow_run`, and pushing `npm-v<version>` is
   the manual fallback for when it did not. Verify:
   `npx innerwarden@<version> --version`.
3. **.deb / .rpm**: nothing to run, and nothing to upload.
   `linux-packages.yml` chains off the same completion and uploads the packages
   to the rolling release itself.

   Previous versions' package assets are deliberately NOT deleted. The runbook
   used to say to delete them; the site links versioned `.deb`/`.rpm`
   filenames, so removing an old asset 404s a documented download. The rolling
   release therefore accumulates packages, which is the intended state rather
   than an oversight.
4. **Site doc**: update the versioned `.deb`/`.rpm` filenames in
   `inner-warden-site` `client/src/content/docs/installation.md`.
5. **Verify**: spot-check one binary signature, run the live installer once, and
   `npm audit signatures`.

---

## Notes and gotchas

- **npm 2FA / tokens (2025+).** Classic and automation npm tokens were revoked
  (Nov 2025). Publishing now requires 2FA **or** a granular token with "Bypass
  2FA" enabled. **Do not create a bypass-2FA token**: it weakens the token and
  npm is deprecating that path. Use the OIDC workflow. The account's 2FA is a
  hardware security key (WebAuthn), so there is no TOTP code for a CLI
  `--otp`; OIDC avoids the problem entirely. The very first publish (before OIDC
  could be configured, since npm needs a package to exist before you can add a
  Trusted Publisher) was done interactively via npm's browser session auth.
- **Transient E404 on the unscoped main package.** During an OIDC publish the six
  scoped `@innerwarden/cli-*` packages can succeed while the unscoped
  `innerwarden` package returns `E404 Not Found - PUT .../innerwarden` (the
  provenance statement is even published first). It is intermittent: just re-run
  the workflow. The publish script is idempotent, so the already-published scoped
  packages are skipped and only the main package is retried.
- **No apt/yum repo yet.** Users install the `.deb`/`.rpm` **file** (`apt install
  ./file.deb`), not `apt install innerwarden`. A hosted, signed repo (for
  `apt update` + auto-upgrade) is a future step; it can be hosted on GitHub with
  our own key, no third-party account.
- **`cargo install innerwarden` / `cargo binstall`** activate once the crate is
  published to crates.io.
- **The release build needs bubblewrap.** The AI Jail tests require a real
  `bwrap` binary and unprivileged user namespaces, and fail rather than silently
  skip isolation, so `release-guard.yml` installs bubblewrap and relaxes the
  Ubuntu 24.04 AppArmor userns restriction. Do not "fix" a jail-test failure by
  skipping the test.
- **Keep this file current.** If you add a channel, change a workflow, or change
  the signing scheme, update this doc in the same PR.
