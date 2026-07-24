# InnerWarden (public Community repo): guidance

Open-source runtime guardrail for AI agents. Screens the shell commands and
MCP/tool calls an AI agent tries to run and returns allow / review / deny.
Binary: `innerwarden`. Apache-2.0. Linux and macOS first-class; Windows
experimental.

Crates: `cli` (the `innerwarden` binary), `agent-guard` (screening engine),
`dashboard-kit` (local dashboard UI), `graph`, `notify`.

## Distribution, install, and releases: read this first

**For anything about how the CLI is packaged, published, signed, verified, or
re-published on a new version, read [DISTRIBUTION.md](DISTRIBUTION.md).** It is
the single source of truth and covers npm (OIDC publishing + provenance),
`.deb`/`.rpm` (nfpm), the signed binaries, the shell installer, Ed25519 signing
and verification, and the full cut-a-release checklist.

Distribution lives in:

- `npm/`: the seven npm packages + build/publish scripts.
- `packaging/`: nfpm config + the `.deb`/`.rpm` build script.
- `.github/workflows/npm-publish.yml`: publish npm via OIDC.
- `.github/workflows/linux-packages.yml`: build + test-install `.deb`/`.rpm`.

The user-facing install page is
<https://innerwarden.com/docs/installation> (source in the `inner-warden-site`
repo, `client/src/content/docs/installation.md`); keep it and DISTRIBUTION.md in
sync when a channel changes.

## Conventions

- Commits in English. Author is the operator; no AI co-author trailer.
- Open a PR (never push straight to a default branch) and wait for CI green.
- See [CONTRIBUTING.md](CONTRIBUTING.md) and [README.md](README.md) for the rest.
