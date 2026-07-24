# innerwarden

Open-source guardrail for AI coding agents. InnerWarden screens the shell
commands and MCP/tool calls your agent runs and returns **allow / review /
deny**, before they run.

Same install on Linux, macOS, and Windows, no `curl | sh`, no `sudo`:

```sh
npm install -g innerwarden
```

or run it without installing:

```sh
npx innerwarden --help
```

## How the install works

This package ships **prebuilt, signed binaries** inside per-platform packages
(`@innerwarden/cli-linux-x64`, `@innerwarden/cli-darwin-arm64`,
`@innerwarden/cli-win32-x64`, ...). npm downloads only the one that matches your
OS and CPU via the standard `os`/`cpu` fields.

There is **no postinstall script and no download at install time** (the esbuild
/ biome model), so `npm install --ignore-scripts` works and there is nothing to
audit beyond the registry tarball itself.

## Quick start

```sh
innerwarden serve          # local check-command API for your agent (127.0.0.1:8787)
innerwarden dashboard      # local dashboard (127.0.0.1:8788)
innerwarden --help
```

## Supported platforms

| OS      | x64 | arm64 |
| ------- | --- | ----- |
| Linux   | yes | yes   |
| macOS   | yes | yes   |
| Windows | yes | yes   |

## Links

- Site: <https://innerwarden.com>
- Source: <https://github.com/InnerWarden/inner-warden>
- License: Apache-2.0

## Maintainer notes

Releases publish from CI via GitHub OIDC trusted publishing (no npm token, no
2FA bypass, signed provenance). Bump the version in `package.json`, then run the
`Publish to npm (OIDC)` workflow or push a `npm-v*` tag.

Local build / manual publish (requires npm 2FA at publish time):

```sh
node scripts/build.mjs      # download binaries, assemble npm/platforms/*
node scripts/publish.mjs --dry-run
node scripts/publish.mjs    # npm will prompt for your authenticator code
```
