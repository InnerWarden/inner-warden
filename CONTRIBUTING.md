# Contributing to InnerWarden

Thanks for helping build a better guardrail for AI agents. This guide covers how
to build, test, and submit changes.

## Build and test

InnerWarden is a Rust workspace. A stable Rust toolchain is all you
need.

```sh
cargo build --release          # build the workspace
cargo test --workspace         # run all tests
cargo fmt --all --check        # confirm formatting
cargo clippy --workspace -- -D warnings   # lint, warnings are errors
```

Run all four locally and confirm they pass before you open a pull request.

CI runs those four on Linux, macOS, and Windows, plus four gates the list above
does not cover, so "all four pass" is not the same as "CI will be green":

- `cargo deny check` (advisories, licences, bans, sources). Run it for any
  dependency change.
- The dashboard bundle: for any change under `crates/dashboard-kit/web`, run
  `npm ci && npm run build` there and commit the rebuilt `dist/`, or
  `npm run bundle:check` fails because the committed bundle no longer matches
  its sources.
- The packaging verifier (`node npm/scripts/verify-release-asset.test.mjs`),
  which also proves itself against a real published artifact.
- The npm/Cargo version agreement, including the six pinned
  `optionalDependencies`.

The Windows test run reports but does not gate yet; its known-rough file-write
cases would otherwise block unrelated work. A Windows failure is still a real
failure, so read it.

## Code style

- Format with `cargo fmt`. The `--check` gate must be clean.
- Keep `cargo clippy --workspace -- -D warnings` clean. Fix the lint rather than
  suppressing it, unless there is a clear reason (note it if you must allow).
- Add tests in the same change as the code they cover.
- Keep commit messages in English and describe the why, not just the what.

## Contribution terms (inbound = outbound)

Contributions are accepted under the same license as the project: Apache-2.0.
By submitting a contribution you agree it is licensed under Apache-2.0 (inbound
license matches outbound license).

There is no CLA. Instead, we use the Developer Certificate of Origin (DCO). Every
commit must be signed off, certifying that you have the right to submit the work
under the project's license. Add the sign-off with:

```sh
git commit -s
```

This appends a `Signed-off-by` line using your `git` name and email. The DCO text
is at https://developercertificate.org. If you forget the sign-off on an existing
commit, amend it with `git commit -s --amend`.

## Submitting a pull request

1. Fork the repository and create a branch.
2. Make your change, with tests, and sign off each commit (`git commit -s`).
3. Run the build, test, fmt, and clippy commands above until they pass.
4. Open a pull request describing the change and its motivation.
