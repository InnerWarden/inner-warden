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
| Signed binaries (`innerwarden-<os>-<arch>` + `.sha256` + `.sig`) | the private `innerwarden` monorepo, `release-guard.yml` | rolling `iw-guard` release on `InnerWarden/innerwarden-releases` | n/a (upstream) |
| npm packages (7: `innerwarden` + 6 `@innerwarden/cli-<os>-<arch>`) | the binaries above | npmjs.com | `npm/` + `.github/workflows/npm-publish.yml` |
| `.deb` / `.rpm` (amd64 + arm64) | the binaries above, via nfpm | attached to the `iw-guard` release | `packaging/` + `.github/workflows/linux-packages.yml` |
| Shell installer (`curl \| sh`) | n/a | `innerwarden.com/free` -> installer script | `iw-guard-install.sh` (monorepo) |

**Everything wraps the same signed binaries.** The binaries are the root of
trust; npm, deb, rpm, Scoop, ubi/eget/mise all fetch or embed them.

---

## Install methods (summary)

Full detail + copy-paste commands: <https://innerwarden.com/docs/installation>.

- **npm (recommended, all OSes):** `npm install -g innerwarden` / `npx innerwarden`. Prebuilt, signed provenance, no sudo, no postinstall.
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
- `npm/scripts/build.mjs` downloads the binaries from the `iw-guard` release and
  assembles `npm/platforms/*` (gitignored).
- `npm/scripts/publish.mjs` publishes the platform packages first, then the main
  package. Idempotent (skips already-published versions), supports `NPM_OTP` and
  `NPM_PROVENANCE=1`.

### Publishing (OIDC, no token)

Publishing runs from CI via **GitHub OIDC trusted publishing** with a signed
provenance attestation. There is no long-lived npm token.

To publish a new version:

1. Bump `version` in `npm/package.json` **and** the six `optionalDependencies`
   versions to match (they are pinned exact).
2. Run the **Publish to npm (OIDC)** workflow (`npm-publish.yml`), or push a tag
   `npm-v<version>`.
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

1. Run the **Linux packages** workflow (`linux-packages.yml`); confirm the
   test-install steps pass.
2. Download the `linux-packages` artifact and attach the files to the release:
   `gh release upload iw-guard --repo InnerWarden/innerwarden-releases *.deb *.rpm *.sha256`
   (the workflow does not auto-attach yet; that is a follow-up).
3. Generate + upload `.sha256` sidecars alongside each package.

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

1. **Binaries**: cut them upstream: the `innerwarden` monorepo
   `release-guard.yml` (`workflow_dispatch` or a `guard-v*` tag) rebuilds and
   signs the per-arch binaries and updates the rolling `iw-guard` release on
   `InnerWarden/innerwarden-releases`.
2. **npm**: bump `npm/package.json` (main + the six optionalDependencies), then
   run `npm-publish.yml` (or push `npm-v<version>`). Verify:
   `npx innerwarden@<version> --version`.
3. **.deb / .rpm**: run `linux-packages.yml`, download the artifact, and
   `gh release upload iw-guard ... *.deb *.rpm *.sha256`.
4. **Site doc**: if the `.deb`/`.rpm` filenames carry the version, update the
   examples in `inner-warden-site` `client/src/content/docs/installation.md`.
5. **Verify**: spot-check one binary signature and `npm audit signatures`.

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
  published to crates.io (`[package.metadata.binstall]` mapping is already in the
  monorepo's `guard-cli`).
- **Keep this file current.** If you add a channel, change a workflow, or change
  the signing scheme, update this doc in the same PR.
