# innerwarden

Open-source guardrail for AI coding agents. InnerWarden screens the shell
commands and MCP/tool calls your agent runs and returns **allow / review /
deny**, before they run.

Same install on Linux, macOS, and Windows:

```sh
npm install -g innerwarden
innerwarden setup
```

**The second line is not optional here.** npm runs nothing at install time, on
purpose: there is no postinstall script, so `npm install --ignore-scripts`
works and nothing executes on your machine before you ask it to. That is a
property worth keeping, and it means npm hands you a binary and stops.

The shell installer at `innerwarden.com/free` opens the same wizard for you
when it finishes. Installing by npm, you open it yourself. Both arrive at the
same place: `setup` picks which agents to guard, starts them in dry run, and
optionally wires alerts.

**On Linux, expect this to need `sudo`.** `npm install -g` writes to npm's
global prefix, and on a distro-packaged Node that prefix is
`/usr/local/lib/node_modules`, owned by root, so the command exits `EACCES`
before InnerWarden is involved at all. Measured on a clean Ubuntu 26.04 machine.
Either give it root, or point npm at a prefix you own:

```sh
sudo npm install -g innerwarden
# or, entirely in your own directory:
npm config set prefix ~/.npm-global   # then put ~/.npm-global/bin on PATH
```

InnerWarden itself never needs root. If you would rather not involve npm's
prefix at all, the shell installer verifies the signed binary and installs it
into `~/.local/bin` with no elevation on any platform:

```sh
curl -fsSL https://innerwarden.com/free | sh          # macOS and Linux
irm https://innerwarden.com/free.ps1 | iex            # Windows PowerShell
```

Or run it without installing anything:

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
